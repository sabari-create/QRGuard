from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_file
)

from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth

import cv2
import os
import sqlite3
import ipaddress
import io
import html
import hashlib
import secrets
import re

from urllib.parse import urlparse, unquote
from functools import wraps

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


# ============================================================
# QRGuard
# QR-Code Phishing Detection System
# ============================================================


app = Flask(
    __name__,
    template_folder=os.path.dirname(
        os.path.abspath(__file__)
    ),
    static_folder=os.path.dirname(
        os.path.abspath(__file__)
    ),
    static_url_path=""
)


# ============================================================
# VERCEL / PROXY SUPPORT
# ============================================================

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1
)


# ============================================================
# SECRET KEY
# ============================================================

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "QRGuard-Local-Project-Secret-Key-2026"
)


app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True
)


# ============================================================
# DATABASE PATH
# ============================================================

if os.environ.get("VERCEL"):

    DB_NAME = "/tmp/qrgurad.db"

else:

    BASE_DIR = os.path.dirname(
        os.path.abspath(__file__)
    )

    DB_NAME = os.path.join(
        BASE_DIR,
        "qrgurad.db"
    )


# ============================================================
# UPLOAD LIMIT
# ============================================================

MAX_FILE_SIZE = 5 * 1024 * 1024


app.config[
    "MAX_CONTENT_LENGTH"
] = MAX_FILE_SIZE


ALLOWED_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "webp",
    "bmp"
}


# ============================================================
# DEMO ADMIN
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


google = None


if (
    GOOGLE_CLIENT_ID
    and GOOGLE_CLIENT_SECRET
):

    google = oauth.register(

        name="google",

        client_id=GOOGLE_CLIENT_ID,

        client_secret=GOOGLE_CLIENT_SECRET,

        server_metadata_url=(
            "https://accounts.google.com/"
            ".well-known/openid-configuration"
        ),

        client_kwargs={
            "scope":
                "openid email profile"
        }
    )


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
    # USERS TABLE
    # --------------------------------------------------------

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT UNIQUE NOT NULL,

            email TEXT UNIQUE NOT NULL,

            password_hash TEXT,

            password_salt TEXT,

            google_id TEXT UNIQUE,

            display_name TEXT,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP
        )
    """)


    # --------------------------------------------------------
    # SCANS TABLE
    # --------------------------------------------------------

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            url TEXT NOT NULL,

            score INTEGER NOT NULL,

            risk TEXT NOT NULL,

            scanned_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP
        )
    """)


    # --------------------------------------------------------
    # MIGRATION: USERS
    # --------------------------------------------------------

    user_columns = [
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    ]


    if "password_salt" not in user_columns:

        connection.execute(
            """
            ALTER TABLE users
            ADD COLUMN password_salt TEXT
            """
        )


    if "google_id" not in user_columns:

        connection.execute(
            """
            ALTER TABLE users
            ADD COLUMN google_id TEXT
            """
        )


    if "display_name" not in user_columns:

        connection.execute(
            """
            ALTER TABLE users
            ADD COLUMN display_name TEXT
            """
        )


    # --------------------------------------------------------
    # MIGRATION: SCANS
    # --------------------------------------------------------

    scan_columns = [
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(scans)"
        ).fetchall()
    ]


    if "user_id" not in scan_columns:

        connection.execute(
            """
            ALTER TABLE scans
            ADD COLUMN user_id INTEGER
            """
        )


    connection.commit()


    # --------------------------------------------------------
    # CREATE DEMO ADMIN
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

        password_hash = generate_password_hash(
            DEMO_PASSWORD
        )

        connection.execute(
            """
            INSERT INTO users
            (
                username,
                email,
                password_hash,
                password_salt,
                display_name
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                DEMO_USERNAME,
                DEMO_EMAIL,
                password_hash,
                None,
                "QRGuard Administrator"
            )
        )


    connection.commit()

    connection.close()


# ============================================================
# INITIALIZE DATABASE
# ============================================================

init_db()


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
        SELECT
            id,
            username,
            email,
            display_name
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()


    connection.close()


    return user


# ============================================================
# FILE VALIDATION
# ============================================================

def allowed_file(filename):

    return (

        bool(filename)

        and "." in filename

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

        details.append({
            "indicator": indicator,
            "points": points
        })


    # --------------------------------------------------------
    # 1. URL LENGTH
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
    # 3. IP ADDRESS
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
    # 4. USERNAME / PASSWORD
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
    # 5. @ SYMBOL
    # --------------------------------------------------------

    if "@" in url:

        add_indicator(
            "@ symbol detected in URL",
            10
        )


    # --------------------------------------------------------
    # 6. SUSPICIOUS KEYWORDS
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
    # 7. MULTIPLE SUBDOMAINS
    # --------------------------------------------------------

    if hostname.count(".") >= 3:

        add_indicator(
            "Multiple subdomains detected",
            10
        )


    # --------------------------------------------------------
    # 8. HYPHEN
    # --------------------------------------------------------

    if "-" in hostname:

        add_indicator(
            "Hyphen detected in hostname",
            5
        )


    # --------------------------------------------------------
    # 9. MULTIPLE DIGITS
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
    # 10. LONG HOSTNAME
    # --------------------------------------------------------

    if len(hostname) > 30:

        add_indicator(
            "Hostname is unusually long",
            10
        )


    # --------------------------------------------------------
    # 11. ENCODED / UNUSUAL CHARACTERS
    # --------------------------------------------------------

    if (
        "%" in url
        or "_" in url
    ):

        add_indicator(
            "Encoded or unusual URL characters detected",
            5
        )


    # --------------------------------------------------------
    # 12. URL DECODING
    # --------------------------------------------------------

    try:

        decoded_url = unquote(url)

        if decoded_url != url:

            add_indicator(
                "URL contains encoded characters",
                10
            )

    except Exception:

        pass


    # --------------------------------------------------------
    # 13. LONG PATH
    # --------------------------------------------------------

    if len(path) > 60:

        add_indicator(
            "URL path is unusually long",
            10
        )


    # --------------------------------------------------------
    # 14. QUERY PARAMETERS
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
    # 15. SUSPICIOUS EXTENSION
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
    # 16. PUNYCODE
    # --------------------------------------------------------

    if "xn--" in hostname.lower():

        add_indicator(
            "Punycode domain detected",
            15
        )


    # --------------------------------------------------------
    # 17. MULTIPLE HYPHENS
    # --------------------------------------------------------

    if hostname.count("-") >= 3:

        add_indicator(
            "Multiple hyphens detected in hostname",
            10
        )


    # --------------------------------------------------------
    # 18. NON-STANDARD PORT
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
    # 19. LONG HOSTNAME LABEL
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
    # SCORE LIMIT
    # --------------------------------------------------------

    score = min(
        score,
        100
    )


    # --------------------------------------------------------
    # RISK
    # --------------------------------------------------------

    if score <= 30:

        risk = "LOW RISK"

    elif score <= 60:

        risk = "MEDIUM RISK"

    else:

        risk = "HIGH RISK"


    # --------------------------------------------------------
    # NO INDICATORS
    # --------------------------------------------------------

    if not reasons:

        reasons.append(
            "No major suspicious indicators detected"
        )

        details.append({
            "indicator":
                "No major suspicious indicators detected",
            "points": 0
        })


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
            url_for("dashboard")
        )


    error = None


    if request.method == "POST":

        username_or_email = request.form.get(
            "username",
            ""
        ).strip()


        password = request.form.get(
            "password",
            ""
        )


        if not username_or_email or not password:

            error = (
                "Please enter username/email and password."
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
                and check_password_hash(
                    user["password_hash"],
                    password
                )
            ):

                session.clear()

                session["user_id"] = user["id"]

                session["username"] = user["username"]

                session["email"] = user["email"]

                session["display_name"] = (
                    user["display_name"]
                    or user["username"]
                )


                return redirect(
                    url_for("dashboard")
                )


            error = (
                "Invalid username/email or password."
            )


    return render_template(
        "login.html",
        error=error
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
            url_for("dashboard")
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


        # ----------------------------------------------------
        # USERNAME
        # ----------------------------------------------------

        if not re.fullmatch(
            r"[A-Za-z0-9_.-]{3,50}",
            username
        ):

            error = (
                "Username must contain 3-50 letters, "
                "numbers, dots, underscores or hyphens."
            )


        # ----------------------------------------------------
        # EMAIL
        # ----------------------------------------------------

        elif not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            email
        ):

            error = (
                "Please enter a valid email address."
            )


        # ----------------------------------------------------
        # PASSWORD
        # ----------------------------------------------------

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
                    "Email address is already registered."
                )


            else:

                password_hash = generate_password_hash(
                    password
                )


                cursor = connection.execute(
                    """
                    INSERT INTO users
                    (
                        username,
                        email,
                        password_hash,
                        password_salt,
                        display_name
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        username,
                        email,
                        password_hash,
                        None,
                        username
                    )
                )


                connection.commit()


                user_id = cursor.lastrowid


                connection.close()


                session.clear()

                session["user_id"] = user_id

                session["username"] = username

                session["email"] = email

                session["display_name"] = username


                return redirect(
                    url_for("dashboard")
                )


            connection.close()


    return render_template(
        "register.html",
        error=error
    )


# ============================================================
# GOOGLE LOGIN
# ============================================================

@app.route("/auth/google")
def google_login():

    if google is None:

        return redirect(
            url_for(
                "login",
                google_error="Google login is not configured."
            )
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

            userinfo = google.userinfo()


        google_id = userinfo.get(
            "sub"
        )


        email = (
            userinfo.get("email")
            or ""
        ).strip().lower()


        display_name = (
            userinfo.get("name")
            or email.split("@")[0]
        ).strip()


        if not google_id or not email:

            return redirect(
                url_for("login")
            )


        connection = get_db()


        # ----------------------------------------------------
        # FIND BY GOOGLE ID
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
        # FIND BY EMAIL
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


            if user:

                connection.execute(
                    """
                    UPDATE users
                    SET google_id = ?,
                        display_name = ?
                    WHERE id = ?
                    """,
                    (
                        google_id,
                        display_name,
                        user["id"]
                    )
                )


        # ----------------------------------------------------
        # CREATE NEW USER
        # ----------------------------------------------------

        if user is None:

            base_username = re.sub(
                r"[^A-Za-z0-9_.-]",
                "",
                email.split("@")[0]
            )


            if len(base_username) < 3:

                base_username = "googleuser"


            base_username = base_username[:40]


            username = base_username


            counter = 1


            while True:

                existing = connection.execute(
                    """
                    SELECT id
                    FROM users
                    WHERE username = ?
                    """,
                    (username,)
                ).fetchone()


                if not existing:

                    break


                username = (
                    f"{base_username}{counter}"
                )

                counter += 1


            cursor = connection.execute(
                """
                INSERT INTO users
                (
                    username,
                    email,
                    password_hash,
                    password_salt,
                    google_id,
                    display_name
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    email,
                    None,
                    None,
                    google_id,
                    display_name
                )
            )


            connection.commit()


            user_id = cursor.lastrowid


            user = connection.execute(
                """
                SELECT *
                FROM users
                WHERE id = ?
                """,
                (user_id,)
            ).fetchone()


        else:

            connection.commit()


        connection.close()


        # ----------------------------------------------------
        # LOGIN SESSION
        # ----------------------------------------------------

        session.clear()


        session["user_id"] = user["id"]

        session["username"] = user["username"]

        session["email"] = user["email"]

        session["display_name"] = (
            user["display_name"]
            or display_name
            or user["username"]
        )


        return redirect(
            url_for("dashboard")
        )


    except Exception as exception:

        print(
            "Google OAuth Error:",
            exception
        )


        return redirect(
            url_for("login")
        )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()


    return redirect(
        url_for("login")
    )


# ============================================================
# MAIN SCANNER
# ============================================================

@app.route("/")
@login_required
def index():

    return render_template(
        "index.html"
    )


# ============================================================
# SCAN
# ============================================================

@app.route(
    "/scan",
    methods=["POST"]
)
@login_required
def scan():

    error = None


    user_id = session.get(
        "user_id"
    )


    # --------------------------------------------------------
    # FILE
    # --------------------------------------------------------

    file = request.files.get(
        "qr_file"
    )


    if file is None:

        file = request.files.get(
            "qr_image"
        )


    if file is None:

        error = (
            "Please select a QR image."
        )

        return render_template(
            "index.html",
            error=error
        )


    # --------------------------------------------------------
    # EMPTY FILE
    # --------------------------------------------------------

    if not file.filename:

        error = (
            "No file selected. Please choose a QR image."
        )

        return render_template(
            "index.html",
            error=error
        )


    # --------------------------------------------------------
    # EXTENSION
    # --------------------------------------------------------

    if not allowed_file(
        file.filename
    ):

        error = (
            "Unsupported image format. "
            "Use PNG, JPG, JPEG, WEBP or BMP."
        )

        return render_template(
            "index.html",
            error=error
        )


    try:

        # ----------------------------------------------------
        # READ IMAGE DIRECTLY INTO MEMORY
        # ----------------------------------------------------

        image_bytes = file.read()


        if not image_bytes:

            error = (
                "Uploaded image is empty."
            )

            return render_template(
                "index.html",
                error=error
            )


        if len(image_bytes) > MAX_FILE_SIZE:

            error = (
                "File is too large. "
                "Maximum allowed size is 5 MB."
            )

            return render_template(
                "index.html",
                error=error
            )


        # ----------------------------------------------------
        # CONVERT TO NUMPY
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

            error = (
                "Unable to read the uploaded image. "
                "Please upload a valid image file."
            )

            return render_template(
                "index.html",
                error=error
            )


        # ----------------------------------------------------
        # QR DETECTOR
        # ----------------------------------------------------

        detector = cv2.QRCodeDetector()


        data, points, _ = (
            detector.detectAndDecode(
                image
            )
        )


        # ----------------------------------------------------
        # QR NOT FOUND
        # ----------------------------------------------------

        if not data:

            error = (
                "No readable QR code was detected. "
                "Please upload a clear QR image."
            )

            return render_template(
                "index.html",
                error=error
            )


        # ----------------------------------------------------
        # URL
        # ----------------------------------------------------

        url = data.strip()


        # ----------------------------------------------------
        # VALIDATE
        # ----------------------------------------------------

        valid, validation_error = (
            validate_url(url)
        )


        if not valid:

            error = validation_error

            return render_template(
                "index.html",
                error=error
            )


        # ----------------------------------------------------
        # ANALYZE
        # ----------------------------------------------------

        (
            score,
            risk,
            reasons,
            details
        ) = analyze_url(url)


        # ----------------------------------------------------
        # SAVE
        # ----------------------------------------------------

        scan_id = save_scan(
            user_id,
            url,
            score,
            risk
        )


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
            result=result
        )


    except cv2.error:

        error = (
            "The image could not be processed. "
            "Please upload a valid QR image."
        )


        return render_template(
            "index.html",
            error=error
        )


    except sqlite3.Error as exception:

        print(
            "SQLite Error:",
            exception
        )


        error = (
            "Database error occurred. "
            "Please try again."
        )


        return render_template(
            "index.html",
            error=error
        )


    except Exception as exception:

        print(
            "QRGuard Scan Error:",
            exception
        )


        error = (
            "An unexpected error occurred "
            "while processing the QR image."
        )


        return render_template(
            "index.html",
            error=error
        )


# ============================================================
# HISTORY
# ============================================================

@app.route("/history")
@login_required
def history():

    user_id = session.get(
        "user_id"
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
        (user_id,)
    ).fetchall()


    connection.close()


    return render_template(
        "history.html",
        scans=scans
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():

    user_id = session.get(
        "user_id"
    )


    connection = get_db()


    total = connection.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE user_id = ?
        """,
        (user_id,)
    ).fetchone()[0]


    low = connection.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE user_id = ?
        AND risk = ?
        """,
        (
            user_id,
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
            user_id,
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
            user_id,
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
        (user_id,)
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
        recent_scans=recent_scans
    )


# ============================================================
# PDF REPORT
# ============================================================

@app.route(
    "/report/<int:scan_id>"
)
@login_required
def report(scan_id):

    user_id = session.get(
        "user_id"
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
            user_id
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


    (
        _,
        _,
        reasons,
        details
    ) = analyze_url(url)


    score = stored_score

    risk = stored_risk


    # --------------------------------------------------------
    # PDF BUFFER
    # --------------------------------------------------------

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
    # HEADER
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
                colors.HexColor("#0b2239")
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
    # SCAN INFORMATION
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
                colors.HexColor("#eaf2f8")
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
    # RISK ASSESSMENT
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
                    f"<font size='24'>{score}/100</font>",
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
                colors.HexColor("#eef3f7")
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
    # DETECTION INDICATORS
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
                colors.HexColor("#0b2239")
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
    # SCORE BREAKDOWN
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
                colors.HexColor("#0b2239")
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
    # METHODOLOGY
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
    # SECURITY NOTICE
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
                colors.HexColor("#fff3cd")
            ),

            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.7,
                colors.HexColor("#d39e00")
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
    # DISCLAIMER
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

@app.route("/health")
def health():

    return {
        "status": "ok",
        "application": "QRGuard",
        "version": "2026"
    }


# ============================================================
# FILE TOO LARGE
# ============================================================

@app.errorhandler(413)
def file_too_large(error):

    if "user_id" in session:

        return render_template(
            "index.html",
            error=(
                "File is too large. "
                "Maximum allowed size is 5 MB."
            )
        ), 413


    return redirect(
        url_for("login")
    )


# ============================================================
# PAGE NOT FOUND
# ============================================================

@app.errorhandler(404)
def page_not_found(error):

    if "user_id" in session:

        return render_template(
            "index.html",
            error="The requested page was not found."
        ), 404


    return redirect(
        url_for("login")
    )


# ============================================================
# INTERNAL SERVER ERROR
# ============================================================

@app.errorhandler(500)
def internal_server_error(error):

    print(
        "Internal Server Error:",
        error
    )


    if "user_id" in session:

        return render_template(
            "index.html",
            error=(
                "A server error occurred. "
                "Please try again."
            )
        ), 500


    return redirect(
        url_for("login")
    )


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
