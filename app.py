from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_file
)

import cv2
import os
import sqlite3
import ipaddress
import io
import html
import hashlib
import hmac
import secrets
from urllib.parse import urlparse, unquote
from functools import wraps

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from authlib.integrations.flask_client import OAuth


# ============================================================
# QRGuard - QR-Code Phishing Detection System
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=BASE_DIR,
    static_folder=BASE_DIR,
    static_url_path=""
)


# ============================================================
# SECRET KEY
# ============================================================

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "QRGuard-Local-Project-Secret-Key-2026"
)


# ============================================================
# UPLOAD CONFIGURATION
# ============================================================

MAX_FILE_SIZE = 5 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "webp",
    "bmp"
}


# Vercel filesystem is read-only.
# /tmp is writable.

if os.environ.get("VERCEL"):
    UPLOAD_FOLDER = "/tmp/qrgurad_uploads"
else:
    UPLOAD_FOLDER = os.path.join(
        BASE_DIR,
        "uploads"
    )

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


# ============================================================
# DATABASE
# ============================================================

if os.environ.get("VERCEL"):
    DB_NAME = "/tmp/qrgurad.db"
else:
    DB_NAME = os.path.join(
        BASE_DIR,
        "qrgurad.db"
    )


# ============================================================
# DEMO LOGIN
# ============================================================

DEMO_USERNAME = "admin"
DEMO_EMAIL = "admin@qrgurad.local"
DEMO_PASSWORD = "qrgurad123"


# ============================================================
# GOOGLE OAUTH
# ============================================================

oauth = OAuth(app)

GOOGLE_CLIENT_ID = os.environ.get(
    "GOOGLE_CLIENT_ID"
)

GOOGLE_CLIENT_SECRET = os.environ.get(
    "GOOGLE_CLIENT_SECRET"
)

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:

    google = oauth.register(
        name="google",

        client_id=GOOGLE_CLIENT_ID,

        client_secret=GOOGLE_CLIENT_SECRET,

        server_metadata_url=(
            "https://accounts.google.com/"
            ".well-known/openid-configuration"
        ),

        client_kwargs={
            "scope": "openid email profile"
        }
    )

else:

    google = None


# ============================================================
# PASSWORD HASHING
# ============================================================

PASSWORD_ITERATIONS = 120000


def hash_password(password):

    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS
    )

    return (
        salt.hex()
        + "$"
        + password_hash.hex()
    )


def verify_password(password, stored_password):

    try:

        salt_hex, hash_hex = (
            stored_password.split("$", 1)
        )

        salt = bytes.fromhex(
            salt_hex
        )

        expected_hash = bytes.fromhex(
            hash_hex
        )

        actual_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PASSWORD_ITERATIONS
        )

        return hmac.compare_digest(
            actual_hash,
            expected_hash
        )

    except Exception:

        return False


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_db():

    connection = sqlite3.connect(
        DB_NAME
    )

    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():

    connection = get_db()

    # --------------------------------------------------------
    # Users table
    # --------------------------------------------------------

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT UNIQUE,
            password_hash TEXT,
            google_id TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # --------------------------------------------------------
    # Scans table
    # --------------------------------------------------------

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            risk TEXT NOT NULL,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # --------------------------------------------------------
    # Migration: google_id
    # --------------------------------------------------------

    try:

        connection.execute(
            "ALTER TABLE users ADD COLUMN google_id TEXT"
        )

    except sqlite3.OperationalError:

        pass

    # --------------------------------------------------------
    # Migration: user_id
    # --------------------------------------------------------

    try:

        connection.execute(
            "ALTER TABLE scans ADD COLUMN user_id INTEGER"
        )

    except sqlite3.OperationalError:

        pass

    connection.commit()

    # --------------------------------------------------------
    # Create demo admin
    # --------------------------------------------------------

    existing_admin = connection.execute(
        """
        SELECT id
        FROM users
        WHERE username = ?
        """,
        (DEMO_USERNAME,)
    ).fetchone()

    if existing_admin is None:

        connection.execute(
            """
            INSERT INTO users
            (
                username,
                email,
                password_hash
            )
            VALUES (?, ?, ?)
            """,
            (
                DEMO_USERNAME,
                DEMO_EMAIL,
                hash_password(
                    DEMO_PASSWORD
                )
            )
        )

        connection.commit()

    connection.close()


# Initialize database

init_db()


# ============================================================
# CURRENT USER
# ============================================================

def get_current_user():

    user_id = session.get(
        "user_id"
    )

    if not user_id:

        return None

    connection = get_db()

    user = connection.execute(
        """
        SELECT id, username, email
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    connection.close()

    return user


# ============================================================
# LOGIN REQUIRED
# ============================================================

def login_required(view_function):

    @wraps(view_function)
    def wrapped_view(*args, **kwargs):

        if "user_id" not in session:

            return redirect(
                url_for("login")
            )

        return view_function(
            *args,
            **kwargs
        )

    return wrapped_view


# ============================================================
# FILE VALIDATION
# ============================================================

def allowed_file(filename):

    return (
        bool(filename)
        and "."
        in filename
        and filename.rsplit(
            ".",
            1
        )[1].lower()
        in ALLOWED_EXTENSIONS
    )


# ============================================================
# URL VALIDATION
# ============================================================

def validate_url(url):

    if not url:

        return (
            False,
            "The QR code did not contain any URL."
        )

    url = url.strip()

    if len(url) > 2048:

        return (
            False,
            "The extracted URL is too long."
        )

    parsed = urlparse(url)

    if parsed.scheme.lower() not in (
        "http",
        "https"
    ):

        return (
            False,
            "QR code does not contain a valid HTTP/HTTPS URL."
        )

    if not parsed.hostname:

        return (
            False,
            "The extracted URL does not contain a valid hostname."
        )

    try:

        _ = parsed.port

    except ValueError:

        return (
            False,
            "Invalid URL port detected."
        )

    return True, None


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_url(url):

    score = 0

    reasons = []

    details = []

    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    path = parsed.path or ""

    query = parsed.query or ""

    def add_indicator(
        indicator,
        points
    ):

        nonlocal score

        score += points

        reasons.append(
            indicator
        )

        details.append(
            {
                "indicator": indicator,
                "points": points
            }
        )

    # --------------------------------------------------------
    # 1. URL length
    # --------------------------------------------------------

    if len(url) > 100:

        add_indicator(
            "URL length is unusually long",
            15
        )

    # --------------------------------------------------------
    # 2. HTTPS
    # --------------------------------------------------------

    if parsed.scheme.lower() != "https":

        add_indicator(
            "HTTPS is not used",
            15
        )

    # --------------------------------------------------------
    # 3. IP address
    # --------------------------------------------------------

    try:

        ipaddress.ip_address(
            hostname
        )

        add_indicator(
            "IP address used instead of domain name",
            25
        )

    except ValueError:

        pass

    # --------------------------------------------------------
    # 4. Username / password
    # --------------------------------------------------------

    if (
        parsed.username
        or parsed.password
    ):

        add_indicator(
            "Username or password is embedded in the URL",
            20
        )

    # --------------------------------------------------------
    # 5. @ symbol
    # --------------------------------------------------------

    if "@" in url:

        add_indicator(
            "@ symbol detected in URL",
            10
        )

    # --------------------------------------------------------
    # 6. Suspicious keywords
    # --------------------------------------------------------

    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "account",
        "update",
        "secure",
        "password",
        "bank",
        "confirm",
        "signin"
    ]

    found_keywords = [
        keyword
        for keyword in suspicious_keywords
        if keyword in url.lower()
    ]

    if found_keywords:

        keyword_text = ", ".join(
            found_keywords
        )

        add_indicator(
            f"Suspicious keywords: {keyword_text}",
            10
        )

    # --------------------------------------------------------
    # 7. Multiple subdomains
    # --------------------------------------------------------

    if hostname.count(".") >= 3:

        add_indicator(
            "Multiple subdomains detected",
            10
        )

    # --------------------------------------------------------
    # 8. Hyphen
    # --------------------------------------------------------

    if "-" in hostname:

        add_indicator(
            "Hyphen detected in hostname",
            5
        )

    # --------------------------------------------------------
    # 9. Multiple digits
    # --------------------------------------------------------

    digit_count = sum(
        character.isdigit()
        for character in hostname
    )

    if digit_count >= 3:

        add_indicator(
            "Multiple digits detected in hostname",
            5
        )

    # --------------------------------------------------------
    # 10. Long hostname
    # --------------------------------------------------------

    if len(hostname) > 30:

        add_indicator(
            "Hostname is unusually long",
            10
        )

    # --------------------------------------------------------
    # 11. Encoded / unusual characters
    # --------------------------------------------------------

    if "%" in url or "_" in url:

        add_indicator(
            "Encoded or unusual URL characters detected",
            5
        )

    # --------------------------------------------------------
    # 12. URL decoding
    # --------------------------------------------------------

    try:

        decoded_url = unquote(
            url
        )

        if decoded_url != url:

            add_indicator(
                "URL contains encoded characters",
                10
            )

    except Exception:

        pass

    # --------------------------------------------------------
    # 13. Long path
    # --------------------------------------------------------

    if len(path) > 60:

        add_indicator(
            "URL path is unusually long",
            10
        )

    # --------------------------------------------------------
    # 14. Query parameters
    # --------------------------------------------------------

    if query:

        parameter_count = len(
            query.split("&")
        )

        if parameter_count >= 4:

            add_indicator(
                "Large number of query parameters detected",
                10
            )

    # --------------------------------------------------------
    # 15. Suspicious executable extension
    # --------------------------------------------------------

    suspicious_extensions = (
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".apk"
    )

    if path.lower().endswith(
        suspicious_extensions
    ):

        add_indicator(
            "Suspicious executable file extension detected",
            15
        )

    # --------------------------------------------------------
    # 16. Punycode
    # --------------------------------------------------------

    if "xn--" in hostname.lower():

        add_indicator(
            "Punycode domain detected",
            15
        )

    # --------------------------------------------------------
    # 17. Multiple hyphens
    # --------------------------------------------------------

    if hostname.count("-") >= 3:

        add_indicator(
            "Multiple hyphens detected in hostname",
            10
        )

    # --------------------------------------------------------
    # 18. Non-standard port
    # --------------------------------------------------------

    try:

        port = parsed.port

        if port and port not in (
            80,
            443
        ):

            add_indicator(
                "Non-standard port detected",
                10
            )

    except ValueError:

        add_indicator(
            "Invalid port information detected",
            10
        )

    # --------------------------------------------------------
    # 19. Very long hostname label
    # --------------------------------------------------------

    hostname_labels = hostname.split(".")

    if any(
        len(label) > 25
        for label in hostname_labels
    ):

        add_indicator(
            "Very long hostname label detected",
            5
        )

    # --------------------------------------------------------
    # Limit score
    # --------------------------------------------------------

    score = min(
        score,
        100
    )

    # --------------------------------------------------------
    # Risk level
    # --------------------------------------------------------

    if score <= 30:

        risk = "LOW RISK"

    elif score <= 60:

        risk = "MEDIUM RISK"

    else:

        risk = "HIGH RISK"

    # --------------------------------------------------------
    # No indicators
    # --------------------------------------------------------

    if not reasons:

        reasons.append(
            "No major suspicious indicators detected"
        )

        details.append(
            {
                "indicator":
                    "No major suspicious indicators detected",
                "points": 0
            }
        )

    return (
        score,
        risk,
        reasons,
        details
    )


# ============================================================
# SAVE SCAN
# ============================================================

def save_scan(
    user_id,
    url,
    score,
    risk
):

    connection = get_db()

    cursor = connection.execute(
        """
        INSERT INTO scans
        (
            user_id,
            url,
            score,
            risk
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            user_id,
            url,
            score,
            risk
        )
    )

    connection.commit()

    scan_id = cursor.lastrowid

    connection.close()

    return scan_id


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if "user_id" in session:

        return redirect(
            url_for("index")
        )

    error = None

    registered = (
        request.args.get(
            "registered"
        )
        == "1"
    )

    if request.method == "POST":

        username_or_email = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username_or_email:

            error = (
                "Please enter your username or email."
            )

        elif not password:

            error = (
                "Please enter your password."
            )

        else:

            connection = get_db()

            user = connection.execute(
                """
                SELECT *
                FROM users
                WHERE username = ?
                   OR email = ?
                """,
                (
                    username_or_email,
                    username_or_email
                )
            ).fetchone()

            connection.close()

            if (
                user
                and user["password_hash"]
                and verify_password(
                    password,
                    user["password_hash"]
                )
            ):

                session.clear()

                session["user_id"] = user["id"]

                session["username"] = (
                    user["username"]
                )

                return redirect(
                    url_for("index")
                )

            error = (
                "Invalid username/email or password."
            )

    return render_template(
        "login.html",
        error=error,
        registered=registered
    )


# ============================================================
# GOOGLE LOGIN
# ============================================================

@app.route(
    "/auth/google"
)
def google_login():

    if google is None:

        return render_template(
            "login.html",
            error=(
                "Google Login is not configured yet."
            ),
            registered=False
        )

    redirect_uri = url_for(
        "google_callback",
        _external=True
    )

    return google.authorize_redirect(
        redirect_uri
    )


# ============================================================
# GOOGLE CALLBACK
# ============================================================

@app.route(
    "/auth/google/callback"
)
def google_callback():

    if google is None:

        return redirect(
            url_for("login")
        )

    try:

        token = google.authorize_access_token()

        userinfo = token.get(
            "userinfo"
        )

        if not userinfo:

            userinfo = google.userinfo(
                token=token
            )

        google_id = userinfo.get(
            "sub"
        )

        email = userinfo.get(
            "email"
        )

        name = (
            userinfo.get("name")
            or userinfo.get("given_name")
            or "Google User"
        )

        if not google_id or not email:

            return render_template(
                "login.html",
                error=(
                    "Google account information could not be retrieved."
                ),
                registered=False
            )

        connection = get_db()

        # ----------------------------------------------------
        # Find by Google ID
        # ----------------------------------------------------

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE google_id = ?
            """,
            (google_id,)
        ).fetchone()

        # ----------------------------------------------------
        # Find by email
        # ----------------------------------------------------

        if user is None:

            user = connection.execute(
                """
                SELECT *
                FROM users
                WHERE email = ?
                """,
                (email,)
            ).fetchone()

        # ----------------------------------------------------
        # Existing account
        # ----------------------------------------------------

        if user is not None:

            connection.execute(
                """
                UPDATE users
                SET google_id = ?
                WHERE id = ?
                """,
                (
                    google_id,
                    user["id"]
                )
            )

            connection.commit()

            user_id = user["id"]

            username = user["username"]

        # ----------------------------------------------------
        # New Google account
        # ----------------------------------------------------

        else:

            base_username = (
                name.strip().lower().replace(
                    " ",
                    "_"
                )
            )

            if not base_username:

                base_username = "google_user"

            username = base_username

            counter = 1

            while True:

                existing_username = connection.execute(
                    """
                    SELECT id
                    FROM users
                    WHERE username = ?
                    """,
                    (username,)
                ).fetchone()

                if existing_username is None:

                    break

                counter += 1

                username = (
                    f"{base_username}_{counter}"
                )

            cursor = connection.execute(
                """
                INSERT INTO users
                (
                    username,
                    email,
                    password_hash,
                    google_id
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    username,
                    email,
                    None,
                    google_id
                )
            )

            connection.commit()

            user_id = cursor.lastrowid

        connection.close()

        session.clear()

        session["user_id"] = user_id

        session["username"] = username

        return redirect(
            url_for("index")
        )

    except Exception as exception:

        print(
            "Google OAuth Error:",
            exception
        )

        return render_template(
            "login.html",
            error=(
                "Google login failed. "
                "Please try again."
            ),
            registered=False
        )


# ============================================================
# REGISTER
# ============================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if "user_id" in session:

        return redirect(
            url_for("index")
        )

    error = None

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if not username:

            error = "Username is required."

        elif len(username) < 3:

            error = (
                "Username must contain at least 3 characters."
            )

        elif not email or "@" not in email:

            error = (
                "Please enter a valid email address."
            )

        elif len(password) < 6:

            error = (
                "Password must contain at least 6 characters."
            )

        elif password != confirm_password:

            error = (
                "Passwords do not match."
            )

        else:

            connection = get_db()

            existing_username = connection.execute(
                """
                SELECT id
                FROM users
                WHERE username = ?
                """,
                (username,)
            ).fetchone()

            existing_email = connection.execute(
                """
                SELECT id
                FROM users
                WHERE email = ?
                """,
                (email,)
            ).fetchone()

            if existing_username:

                error = (
                    "Username already exists."
                )

            elif existing_email:

                error = (
                    "Email already registered."
                )

            else:

                connection.execute(
                    """
                    INSERT INTO users
                    (
                        username,
                        email,
                        password_hash
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        username,
                        email,
                        hash_password(
                            password
                        )
                    )
                )

                connection.commit()

                connection.close()

                return redirect(
                    url_for(
                        "login",
                        registered=1
                    )
                )

            connection.close()

    return render_template(
        "register.html",
        error=error
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route(
    "/logout"
)
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# MAIN PAGE
# ============================================================

@app.route(
    "/",
    methods=["GET"]
)
@login_required
def index():

    user = get_current_user()

    return render_template(
        "index.html",
        user=user
    )


# ============================================================
# QR SCAN
# ============================================================

@app.route(
    "/scan",
    methods=["POST"]
)
@login_required
def scan():

    filepath = None

    try:

        # ----------------------------------------------------
        # File check
        # ----------------------------------------------------

        if "qr_file" not in request.files:

            return render_template(
                "index.html",
                error=(
                    "Please select a QR image."
                )
            )

        file = request.files[
            "qr_file"
        ]

        if not file or file.filename == "":

            return render_template(
                "index.html",
                error=(
                    "No file selected. "
                    "Please choose a QR image."
                )
            )

        # ----------------------------------------------------
        # Extension
        # ----------------------------------------------------

        if not allowed_file(
            file.filename
        ):

            return render_template(
                "index.html",
                error=(
                    "Unsupported image format. "
                    "Use PNG, JPG, JPEG, WEBP or BMP."
                )
            )

        # ----------------------------------------------------
        # Read uploaded image directly into memory
        # ----------------------------------------------------

        image_bytes = file.read()

        if not image_bytes:

            return render_template(
                "index.html",
                error=(
                    "Uploaded image is empty."
                )
            )

        # ----------------------------------------------------
        # Convert bytes to OpenCV image
        # ----------------------------------------------------

        import numpy as np

        image_array = np.frombuffer(
            image_bytes,
            dtype=np.uint8
        )

        image = cv2.imdecode(
            image_array,
            cv2.IMREAD_COLOR
        )

        if image is None:

            return render_template(
                "index.html",
                error=(
                    "Unable to read the uploaded image. "
                    "Please upload a valid image file."
                )
            )

        # ----------------------------------------------------
        # QR detector
        # ----------------------------------------------------

        detector = cv2.QRCodeDetector()

        data = ""

        # First attempt
        try:

            data, points, _ = (
                detector.detectAndDecode(
                    image
                )
            )

        except cv2.error:

            data = ""

        # ----------------------------------------------------
        # Second attempt - resize
        # ----------------------------------------------------

        if not data:

            try:

                height, width = image.shape[:2]

                max_dimension = 1600

                scale = min(
                    1.0,
                    max_dimension
                    / max(
                        height,
                        width
                    )
                )

                if scale < 1.0:

                    resized = cv2.resize(
                        image,
                        None,
                        fx=scale,
                        fy=scale,
                        interpolation=cv2.INTER_AREA
                    )

                else:

                    resized = image

                data, points, _ = (
                    detector.detectAndDecode(
                        resized
                    )
                )

            except cv2.error:

                data = ""

        # ----------------------------------------------------
        # Third attempt - grayscale
        # ----------------------------------------------------

        if not data:

            try:

                gray = cv2.cvtColor(
                    image,
                    cv2.COLOR_BGR2GRAY
                )

                data, points, _ = (
                    detector.detectAndDecode(
                        gray
                    )
                )

            except cv2.error:

                data = ""

        # ----------------------------------------------------
        # QR not detected
        # ----------------------------------------------------

        if not data:

            return render_template(
                "index.html",
                error=(
                    "No readable QR code was detected. "
                    "Please upload a clear QR image."
                )
            )

        # ----------------------------------------------------
        # URL
        # ----------------------------------------------------

        url = data.strip()

        # ----------------------------------------------------
        # Validate
        # ----------------------------------------------------

        valid, validation_error = (
            validate_url(url)
        )

        if not valid:

            return render_template(
                "index.html",
                error=validation_error
            )

        # ----------------------------------------------------
        # Analyze
        # ----------------------------------------------------

        score, risk, reasons, details = (
            analyze_url(url)
        )

        # ----------------------------------------------------
        # Current user
        # ----------------------------------------------------

        user = get_current_user()

        if user is None:

            return redirect(
                url_for("login")
            )

        # ----------------------------------------------------
        # Save scan
        # ----------------------------------------------------

        scan_id = save_scan(
            user["id"],
            url,
            score,
            risk
        )

        # ----------------------------------------------------
        # Result
        # ----------------------------------------------------

        result = {
            "id": scan_id,
            "url": url,
            "score": score,
            "risk": risk,
            "reasons": reasons,
            "details": details
        }

        return render_template(
            "result.html",
            result=result,
            user=user
        )

    except cv2.error:

        return render_template(
            "index.html",
            error=(
                "The image could not be processed. "
                "Please upload a valid QR image."
            )
        )

    except sqlite3.Error as exception:

        print(
            "Database Error:",
            exception
        )

        return render_template(
            "index.html",
            error=(
                "Database error occurred. "
                "Please try again."
            )
        )

    except Exception as exception:

        print(
            "QRGuard Scan Error:",
            exception
        )

        return render_template(
            "index.html",
            error=(
                "An unexpected error occurred "
                "while processing the QR image."
            )
        )

    finally:

        # No uploaded file is permanently stored.
        # QR image is processed directly in memory.
        pass


# ============================================================
# FILE SIZE ERROR
# ============================================================

@app.errorhandler(413)
def file_too_large(error):

    return render_template(
        "index.html",
        error=(
            "File is too large. "
            "Maximum allowed size is 5 MB."
        )
    ), 413


# ============================================================
# PAGE NOT FOUND
# ============================================================

@app.errorhandler(404)
def page_not_found(error):

    if "user_id" in session:

        return render_template(
            "index.html",
            error=(
                "The requested page was not found."
            )
        ), 404

    return redirect(
        url_for("login")
    )


# ============================================================
# INTERNAL SERVER ERROR
# ============================================================

@app.errorhandler(500)
def internal_server_error(error):

    return render_template(
        "login.html",
        error=(
            "A server error occurred. "
            "Please try again."
        ),
        registered=False
    ), 500


# ============================================================
# HISTORY
# ============================================================

@app.route(
    "/history"
)
@login_required
def history():

    user = get_current_user()

    if user is None:

        return redirect(
            url_for("login")
        )

    connection = get_db()

    scans = connection.execute(
        """
        SELECT
            id,
            url,
            score,
            risk,
            scanned_at
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user["id"],)
    ).fetchall()

    connection.close()

    return render_template(
        "history.html",
        scans=scans,
        user=user
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route(
    "/dashboard"
)
@login_required
def dashboard():

    user = get_current_user()

    if user is None:

        return redirect(
            url_for("login")
        )

    connection = get_db()

    total = connection.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE user_id = ?
        """,
        (user["id"],)
    ).fetchone()[0]

    low = connection.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE user_id = ?
        AND risk = ?
        """,
        (
            user["id"],
            "LOW RISK"
        )
    ).fetchone()[0]

    medium = connection.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE user_id = ?
        AND risk = ?
        """,
        (
            user["id"],
            "MEDIUM RISK"
        )
    ).fetchone()[0]

    high = connection.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE user_id = ?
        AND risk = ?
        """,
        (
            user["id"],
            "HIGH RISK"
        )
    ).fetchone()[0]

    recent_scans = connection.execute(
        """
        SELECT
            id,
            url,
            score,
            risk,
            scanned_at
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 5
        """,
        (user["id"],)
    ).fetchall()

    connection.close()

    stats = {
        "total": total,
        "low": low,
        "medium": medium,
        "high": high
    }

    return render_template(
        "dashboard.html",
        stats=stats,
        recent_scans=recent_scans,
        user=user
    )


# ============================================================
# PDF REPORT
# ============================================================

@app.route(
    "/report/<int:scan_id>"
)
@login_required
def report(scan_id):

    user = get_current_user()

    if user is None:

        return redirect(
            url_for("login")
        )

    connection = get_db()

    scan = connection.execute(
        """
        SELECT
            id,
            url,
            score,
            risk,
            scanned_at
        FROM scans
        WHERE id = ?
        AND user_id = ?
        """,
        (
            scan_id,
            user["id"]
        )
    ).fetchone()

    connection.close()

    if scan is None:

        return (
            "Scan record not found.",
            404
        )

    url = scan["url"]

    stored_score = scan["score"]

    stored_risk = scan["risk"]

    scanned_at = scan["scanned_at"]

    # Recalculate indicators for report
    score, risk, reasons, details = (
        analyze_url(url)
    )

    # Keep stored score/risk
    score = stored_score

    risk = stored_risk

    pdf_buffer = io.BytesIO()

    document = SimpleDocTemplate(
        pdf_buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=22,
        leading=26,
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        "SubtitleStyle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=10,
        leading=14,
        spaceAfter=18
    )

    section_style = ParagraphStyle(
        "SectionStyle",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        spaceBefore=10,
        spaceAfter=8
    )

    normal_style = ParagraphStyle(
        "NormalStyle",
        parent=styles["Normal"],
        fontSize=9,
        leading=13
    )

    small_style = ParagraphStyle(
        "SmallStyle",
        parent=styles["Normal"],
        fontSize=8,
        leading=11
    )

    story = []

    # --------------------------------------------------------
    # Header
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "QRGuard",
            title_style
        )
    )

    story.append(
        Paragraph(
            "QR-Code Phishing Detection System",
            subtitle_style
        )
    )

    header_table = Table(
        [
            [
                Paragraph(
                    "<b>SECURITY ANALYSIS REPORT</b>",
                    normal_style
                )
            ]
        ],
        colWidths=[
            174 * mm
        ]
    )

    header_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor(
                    "#0b2239"
                )
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, -1),
                colors.white
            ),
            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER"
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                10
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                10
            )
        ])
    )

    story.append(
        header_table
    )

    story.append(
        Spacer(1, 12)
    )

    # --------------------------------------------------------
    # Scan Information
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "1. Scan Information",
            section_style
        )
    )

    safe_url = html.escape(
        url
    )

    scan_data = [
        [
            "Scan ID",
            str(scan["id"])
        ],
        [
            "Scanned URL",
            Paragraph(
                safe_url,
                small_style
            )
        ],
        [
            "Scanned At",
            str(scanned_at)
        ],
        [
            "User",
            html.escape(
                user["username"]
            )
        ]
    ]

    scan_table = Table(
        scan_data,
        colWidths=[
            40 * mm,
            134 * mm
        ]
    )

    scan_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor(
                    "#eaf2f8"
                )
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(
        scan_table
    )

    story.append(
        Spacer(1, 12)
    )

    # --------------------------------------------------------
    # Risk Assessment
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "2. Risk Assessment",
            section_style
        )
    )

    if risk == "LOW RISK":

        risk_color = colors.HexColor(
            "#198754"
        )

    elif risk == "MEDIUM RISK":

        risk_color = colors.HexColor(
            "#d39e00"
        )

    else:

        risk_color = colors.HexColor(
            "#dc3545"
        )

    risk_table = Table(
        [
            [
                Paragraph(
                    f"<b>RISK SCORE</b><br/>"
                    f"<font size='24'>"
                    f"{score}/100"
                    f"</font>",
                    normal_style
                ),
                Paragraph(
                    f"<b>RISK LEVEL</b><br/>"
                    f"<font size='16'>"
                    f"{html.escape(risk)}"
                    f"</font>",
                    normal_style
                )
            ]
        ],
        colWidths=[
            87 * mm,
            87 * mm
        ]
    )

    risk_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, 0),
                colors.HexColor(
                    "#eef3f7"
                )
            ),
            (
                "BACKGROUND",
                (1, 0),
                (1, 0),
                risk_color
            ),
            (
                "TEXTCOLOR",
                (1, 0),
                (1, 0),
                colors.white
            ),
            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER"
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),
            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.7,
                colors.grey
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                12
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                12
            )
        ])
    )

    story.append(
        risk_table
    )

    story.append(
        Spacer(1, 12)
    )

    # --------------------------------------------------------
    # Detection Indicators
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "3. Detection Indicators",
            section_style
        )
    )

    indicator_rows = [
        [
            "Indicator",
            "Points"
        ]
    ]

    for detail in details:

        indicator_rows.append(
            [
                Paragraph(
                    html.escape(
                        str(
                            detail["indicator"]
                        )
                    ),
                    small_style
                ),
                str(
                    detail["points"]
                )
            ]
        )

    indicator_table = Table(
        indicator_rows,
        colWidths=[
            145 * mm,
            29 * mm
        ],
        repeatRows=1
    )

    indicator_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor(
                    "#0b2239"
                )
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "ALIGN",
                (1, 1),
                (1, -1),
                "CENTER"
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                6
            )
        ])
    )

    story.append(
        indicator_table
    )

    story.append(
        Spacer(1, 12)
    )

    # --------------------------------------------------------
    # Score Breakdown
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "4. Score Breakdown",
            section_style
        )
    )

    breakdown_text = (
        "The QRGuard risk score is calculated using "
        "rule-based URL security indicators. Each "
        "detected indicator contributes a predefined "
        "number of points. The final score is limited "
        "to a maximum of 100."
    )

    story.append(
        Paragraph(
            breakdown_text,
            normal_style
        )
    )

    story.append(
        Spacer(1, 8)
    )

    risk_method_table = Table(
        [
            [
                "Score Range",
                "Classification"
            ],
            [
                "0 - 30",
                "LOW RISK"
            ],
            [
                "31 - 60",
                "MEDIUM RISK"
            ],
            [
                "61 - 100",
                "HIGH RISK"
            ]
        ],
        colWidths=[
            70 * mm,
            104 * mm
        ]
    )

    risk_method_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor(
                    "#0b2239"
                )
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER"
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                6
            )
        ])
    )

    story.append(
        risk_method_table
    )

    story.append(
        Spacer(1, 12)
    )

    # --------------------------------------------------------
    # Methodology
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "5. Security Methodology",
            section_style
        )
    )

    methodology = [
        "QR image is decoded locally using a QR-code detector.",
        "The extracted URL is validated as an HTTP/HTTPS URL.",
        "The URL is analyzed using predefined security heuristics.",
        "Suspicious indicators contribute weighted risk points.",
        "The final score is classified into LOW, MEDIUM, or HIGH risk.",
        "The submitted URL is not automatically opened or visited by QRGuard."
    ]

    for item in methodology:

        story.append(
            Paragraph(
                "• " + item,
                normal_style
            )
        )

        story.append(
            Spacer(1, 3)
        )

    story.append(
        Spacer(1, 8)
    )

    # --------------------------------------------------------
    # Security Notice
    # --------------------------------------------------------

    notice_table = Table(
        [
            [
                Paragraph(
                    "<b>SECURITY NOTICE</b><br/>"
                    "QRGuard performs static URL analysis. "
                    "A risk classification is an automated "
                    "security assessment and should not be "
                    "treated as absolute proof that a website "
                    "is malicious or safe.",
                    small_style
                )
            ]
        ],
        colWidths=[
            174 * mm
        ]
    )

    notice_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor(
                    "#fff3cd"
                )
            ),
            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.7,
                colors.HexColor(
                    "#d39e00"
                )
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                10
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                10
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                10
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                10
            )
        ])
    )

    story.append(
        notice_table
    )

    story.append(
        Spacer(1, 12)
    )

    # --------------------------------------------------------
    # Disclaimer
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "6. Disclaimer",
            section_style
        )
    )

    disclaimer = (
        "This report is generated for educational and "
        "defensive cybersecurity analysis purposes. "
        "QRGuard uses heuristic indicators and may "
        "produce false positives or false negatives. "
        "Users should verify suspicious links through "
        "trusted security resources before interacting "
        "with them."
    )

    story.append(
        Paragraph(
            disclaimer,
            normal_style
        )
    )

    story.append(
        Spacer(1, 18)
    )

    story.append(
        Paragraph(
            "QRGuard © 2026 | Cyber Security Project",
            small_style
        )
    )

    document.build(
        story
    )

    pdf_buffer.seek(0)

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=(
            f"QRGuard_Report_{scan_id}.pdf"
        ),
        mimetype="application/pdf"
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route(
    "/health"
)
def health():

    return {
        "status": "ok",
        "application": "QRGuard"
    }


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )
