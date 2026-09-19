from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_file
)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

from authlib.integrations.flask_client import OAuth

import cv2
import os
import sqlite3
import ipaddress
import io
import html
import re
import secrets
import numpy as np

from urllib.parse import urlparse, unquote
from functools import wraps

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
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

from sklearn.ensemble import RandomForestClassifier


# ============================================================
# QRGuard - QR-Code Phishing Detection System
# ============================================================

app = Flask(
    __name__,
    template_folder=os.path.dirname(os.path.abspath(__file__)),
    static_folder=os.path.dirname(os.path.abspath(__file__)),
    static_url_path=""
)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "QRGuard-Local-Project-Secret-Key-2026"
)

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1
)


# ============================================================
# SESSION CONFIGURATION
# ============================================================

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SESSION_COOKIE_SECURE"] = bool(
    os.environ.get("VERCEL")
)


# ============================================================
# DATABASE
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

if os.environ.get("VERCEL"):

    DB_NAME = "/tmp/qrgurad.db"

else:

    DB_NAME = os.path.join(
        BASE_DIR,
        "qrgurad.db"
    )


# ============================================================
# LOGIN DETAILS
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

# FIXED PRODUCTION GOOGLE CALLBACK
GOOGLE_REDIRECT_URI = os.environ.get(
    "GOOGLE_REDIRECT_URI",
    "https://qr-guard-six.vercel.app/auth/google/callback"
)

google = None

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

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            password_salt TEXT,
            google_id TEXT UNIQUE,
            display_name TEXT,
            profile_photo BLOB,
            profile_photo_mimetype TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            risk TEXT NOT NULL,
            ml_prediction TEXT,
            ml_confidence REAL,
            ml_score INTEGER,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id)
                REFERENCES users(id)
        )
    """)

    existing_columns = [
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    ]

    user_columns = {
        "password_hash": "TEXT",
        "password_salt": "TEXT",
        "google_id": "TEXT",
        "display_name": "TEXT",
        "profile_photo": "BLOB",
        "profile_photo_mimetype": "TEXT"
    }

    for column, datatype in user_columns.items():

        if column not in existing_columns:

            try:

                connection.execute(
                    f"ALTER TABLE users "
                    f"ADD COLUMN {column} {datatype}"
                )

            except sqlite3.Error:
                pass

    scan_columns = [
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(scans)"
        ).fetchall()
    ]

    scan_new_columns = {
        "user_id": "INTEGER",
        "ml_prediction": "TEXT",
        "ml_confidence": "REAL",
        "ml_score": "INTEGER"
    }

    for column, datatype in scan_new_columns.items():

        if column not in scan_columns:

            try:

                connection.execute(
                    f"ALTER TABLE scans "
                    f"ADD COLUMN {column} {datatype}"
                )

            except sqlite3.Error:
                pass

    admin = connection.execute(
        """
        SELECT id
        FROM users
        WHERE username = ?
        """,
        (DEMO_USERNAME,)
    ).fetchone()

    if admin is None:

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
                secrets.token_hex(16),
                "QRGuard Administrator"
            )
        )

    connection.commit()
    connection.close()


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
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    connection.close()

    return user


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
# ML FEATURE EXTRACTION
# ============================================================

def extract_ml_features(url):

    parsed = urlparse(url)

    hostname = (
        parsed.hostname or ""
    ).lower()

    path = (
        parsed.path or ""
    ).lower()

    query = (
        parsed.query or ""
    ).lower()

    full_url = url.lower()

    features = [

        min(len(url), 300),

        min(len(hostname), 100),

        min(len(path), 150),

        min(len(query), 150),

        hostname.count("."),

        hostname.count("-"),

        sum(
            char.isdigit()
            for char in hostname
        ),

        sum(
            char in "@_%=?"
            for char in url
        ),

        int(
            parsed.scheme.lower()
            == "https"
        ),

        int(
            _is_ip_address(hostname)
        ),

        int(
            "xn--" in hostname
        ),

        int(
            parsed.username is not None
        ),

        int(
            parsed.password is not None
        ),

        int(
            bool(query)
        ),

        query.count("&") + 1
        if query
        else 0,

        sum(
            word in full_url
            for word in [
                "login",
                "signin",
                "verify",
                "verification",
                "account",
                "password",
                "secure",
                "bank",
                "confirm",
                "update",
                "wallet",
                "payment",
                "recover"
            ]
        ),

        int(
            full_url.endswith(
                (
                    ".exe",
                    ".scr",
                    ".bat",
                    ".cmd",
                    ".apk"
                )
            )
        ),

        int(
            _has_nonstandard_port(parsed)
        ),

        int(
            "%" in url
        ),

        int(
            hostname.count(".") >= 3
        )
    ]

    return np.array(
        features,
        dtype=float
    )


def _is_ip_address(hostname):

    try:

        ipaddress.ip_address(
            hostname
        )

        return True

    except ValueError:

        return False


def _has_nonstandard_port(parsed):

    try:

        port = parsed.port

        if port is None:
            return False

        return port not in (
            80,
            443
        )

    except ValueError:

        return True


# ============================================================
# ML TRAINING DATA
# ============================================================

def build_ml_training_data():

    safe_urls = [

        "https://google.com",
        "https://www.google.com",
        "https://github.com",
        "https://github.com/login",
        "https://microsoft.com",
        "https://www.microsoft.com",
        "https://apple.com",
        "https://www.apple.com",
        "https://amazon.com",
        "https://www.amazon.com",
        "https://wikipedia.org",
        "https://www.wikipedia.org",
        "https://youtube.com",
        "https://www.youtube.com",
        "https://stackoverflow.com",
        "https://python.org",
        "https://www.python.org",
        "https://example.com",
        "https://example.org",
        "https://www.cloudflare.com",
        "https://www.mozilla.org"
    ]

    phishing_urls = [

        "http://192.168.1.20/login",
        "http://192.168.1.25/verify",
        "http://login-secure-account.com",
        "http://secure-account-verify.com",
        "http://bank-login-confirm.com",
        "http://verify-password-account.com",
        "http://secure-login-update.com",
        "http://account-verification-login.com",
        "http://xn--secure-login-9za.com",
        "http://paypal-login-verify.com",
        "http://amazon-account-verify.com",
        "http://bank-secure-login.com",
        "http://secure-payment-update.com",
        "http://login-confirm-account.com",
        "http://verify-wallet-payment.com",
        "http://account-secure-password.com",
        "http://192.168.1.100:8080/login",
        "http://example.com@phishing-site.com",
        "http://secure--account--verify.com",
        "http://login.verify.account.example.com",
        "http://update-account-password.example.com"
    ]

    X = []
    y = []

    for url in safe_urls:

        X.append(
            extract_ml_features(url)
        )

        y.append(0)

    for url in phishing_urls:

        X.append(
            extract_ml_features(url)
        )

        y.append(1)

    return np.array(X), np.array(y)


# ============================================================
# TRAIN ML MODEL
# ============================================================

def train_ml_model():

    X, y = build_ml_training_data()

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        random_state=42,
        class_weight="balanced"
    )

    model.fit(
        X,
        y
    )

    return model


ML_MODEL = train_ml_model()


# ============================================================
# ML ANALYSIS
# ============================================================

def ml_analyze_url(url):

    features = extract_ml_features(
        url
    ).reshape(1, -1)

    prediction = ML_MODEL.predict(
        features
    )[0]

    probabilities = (
        ML_MODEL.predict_proba(
            features
        )[0]
    )

    phishing_probability = (
        float(probabilities[1])
    )

    confidence = round(
        max(probabilities) * 100,
        2
    )

    ml_score = round(
        phishing_probability * 100
    )

    if prediction == 1:

        prediction_text = (
            "Potential Phishing"
        )

    else:

        prediction_text = (
            "Likely Safe"
        )

    return {
        "prediction": prediction_text,
        "confidence": confidence,
        "score": ml_score
    }


# ============================================================
# RULE-BASED URL ANALYSIS
# ============================================================

def analyze_url(url):

    score = 0
    reasons = []
    details = []

    parsed = urlparse(url)

    hostname = (
        parsed.hostname or ""
    )

    path = (
        parsed.path or ""
    )

    query = (
        parsed.query or ""
    )

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

    if len(url) > 100:

        add_indicator(
            "URL length is unusually long",
            15
        )

    if parsed.scheme.lower() != "https":

        add_indicator(
            "HTTPS is not used",
            15
        )

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

    if (
        parsed.username
        or parsed.password
    ):

        add_indicator(
            "Username or password is embedded in the URL",
            20
        )

    if "@" in url:

        add_indicator(
            "@ symbol detected in URL",
            10
        )

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

    if hostname.count(".") >= 3:

        add_indicator(
            "Multiple subdomains detected",
            10
        )

    if "-" in hostname:

        add_indicator(
            "Hyphen detected in hostname",
            5
        )

    digit_count = sum(
        character.isdigit()
        for character in hostname
    )

    if digit_count >= 3:

        add_indicator(
            "Multiple digits detected in hostname",
            5
        )

    if len(hostname) > 30:

        add_indicator(
            "Hostname is unusually long",
            10
        )

    if "%" in url or "_" in url:

        add_indicator(
            "Encoded or unusual URL characters detected",
            5
        )

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

    if len(path) > 60:

        add_indicator(
            "URL path is unusually long",
            10
        )

    if query:

        parameter_count = len(
            query.split("&")
        )

        if parameter_count >= 4:

            add_indicator(
                "Large number of query parameters detected",
                10
            )

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

    if "xn--" in hostname.lower():

        add_indicator(
            "Punycode domain detected",
            15
        )

    if hostname.count("-") >= 3:

        add_indicator(
            "Multiple hyphens detected",
            10
        )

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

    hostname_labels = hostname.split(".")

    if any(
        len(label) > 25
        for label in hostname_labels
    ):

        add_indicator(
            "Very long hostname label detected",
            5
        )

    score = min(
        score,
        100
    )

    if score <= 30:

        risk = "LOW RISK"

    elif score <= 60:

        risk = "MEDIUM RISK"

    else:

        risk = "HIGH RISK"

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
# COMBINE RULE + ML SCORE
# ============================================================

def combined_analysis(url):

    rule_score, rule_risk, reasons, details = (
        analyze_url(url)
    )

    ml_result = ml_analyze_url(
        url
    )

    ml_score = ml_result["score"]

    combined_score = round(
        (rule_score * 0.70)
        +
        (ml_score * 0.30)
    )

    combined_score = min(
        combined_score,
        100
    )

    if combined_score <= 30:

        final_risk = "LOW RISK"

    elif combined_score <= 60:

        final_risk = "MEDIUM RISK"

    else:

        final_risk = "HIGH RISK"

    details.append({
        "indicator":
            (
                "ML prediction: "
                + ml_result["prediction"]
                + " ("
                + str(ml_result["confidence"])
                + "% confidence)"
            ),
        "points":
            ml_score
    })

    reasons.append(
        "ML prediction: "
        + ml_result["prediction"]
    )

    return {
        "score": combined_score,
        "risk": final_risk,
        "reasons": reasons,
        "details": details,
        "ml_prediction":
            ml_result["prediction"],
        "ml_confidence":
            ml_result["confidence"],
        "ml_score":
            ml_score,
        "rule_score":
            rule_score
    }


# ============================================================
# SAVE SCAN
# ============================================================

def save_scan(
    user_id,
    url,
    score,
    risk,
    ml_prediction,
    ml_confidence,
    ml_score
):

    connection = get_db()

    cursor = connection.execute(
        """
        INSERT INTO scans
        (
            user_id,
            url,
            score,
            risk,
            ml_prediction,
            ml_confidence,
            ml_score
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            url,
            score,
            risk,
            ml_prediction,
            ml_confidence,
            ml_score
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

    error = request.args.get(
        "google_error"
    )

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        connection = get_db()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            OR email = ?
            """,
            (
                username,
                username
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
            session["display_name"] = (
                user["display_name"]
                or user["username"]
            )

            return redirect(
                url_for("index")
            )

        error = (
            "Invalid username or password."
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

        if not username or not email or not password:

            error = (
                "Please fill in all required fields."
            )

        elif password != confirm_password:

            error = (
                "Passwords do not match."
            )

        elif len(password) < 6:

            error = (
                "Password must contain at least 6 characters."
            )

        elif not re.match(
            r"^[A-Za-z0-9_.-]+$",
            username
        ):

            error = (
                "Username contains invalid characters."
            )

        else:

            connection = get_db()

            existing = connection.execute(
                """
                SELECT id
                FROM users
                WHERE username = ?
                OR email = ?
                """,
                (
                    username,
                    email
                )
            ).fetchone()

            if existing:

                error = (
                    "Username or email already exists."
                )

                connection.close()

            else:

                password_hash = (
                    generate_password_hash(
                        password
                    )
                )

                password_salt = (
                    secrets.token_hex(16)
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
                        password_salt,
                        username
                    )
                )

                connection.commit()

                user_id = cursor.lastrowid

                connection.close()

                session.clear()

                session["user_id"] = user_id
                session["username"] = username
                session["display_name"] = username

                return redirect(
                    url_for("index")
                )

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
                google_error=(
                    "Google login is not configured."
                )
            )
        )

    # FIXED PRODUCTION REDIRECT URI
    return google.authorize_redirect(
        GOOGLE_REDIRECT_URI
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

        user_info = token.get(
            "userinfo"
        )

        if not user_info:

            user_info = (
                google.userinfo()
            )

        google_id = str(
            user_info.get("sub")
            or user_info.get("id")
        )

        email = (
            user_info.get("email")
            or ""
        ).lower()

        display_name = (
            user_info.get("name")
            or email.split("@")[0]
        )

        if not google_id or not email:

            return redirect(
                url_for(
                    "login",
                    google_error=(
                        "Google account information could not be retrieved."
                    )
                )
            )

        connection = get_db()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE google_id = ?
            OR email = ?
            """,
            (
                google_id,
                email
            )
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

            user_id = user["id"]
            username = user["username"]

        else:

            base_username = re.sub(
                r"[^A-Za-z0-9_.-]",
                "",
                email.split("@")[0]
            ) or "googleuser"

            username = base_username

            counter = 1

            while connection.execute(
                """
                SELECT id
                FROM users
                WHERE username = ?
                """,
                (username,)
            ).fetchone():

                username = (
                    base_username
                    + str(counter)
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

            user_id = cursor.lastrowid

        connection.commit()
        connection.close()

        session.clear()

        session["user_id"] = user_id
        session["username"] = username
        session["display_name"] = display_name

        return redirect(
            url_for("index")
        )

    except Exception as exception:

        print(
            "Google OAuth Error:",
            exception
        )

        return redirect(
            url_for(
                "login",
                google_error=(
                    "Google login failed. Please try again."
                )
            )
        )


# ============================================================
# PROFILE
# ============================================================

@app.route(
    "/profile",
    methods=["GET", "POST"]
)
@login_required
def profile():

    user_id = session["user_id"]
    error = None
    success = None

    if request.method == "POST":

        action = request.form.get(
            "action",
            ""
        )

        connection = get_db()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

        if user is None:

            connection.close()

            session.clear()

            return redirect(
                url_for("login")
            )

        # ----------------------------------------------------
        # EDIT PROFILE
        # ----------------------------------------------------

        if action == "edit_profile":

            display_name = request.form.get(
                "display_name",
                ""
            ).strip()

            email = request.form.get(
                "email",
                ""
            ).strip().lower()

            if not display_name:

                error = "Display name cannot be empty."

            elif not email or "@" not in email:

                error = "Please enter a valid email address."

            else:

                existing = connection.execute(
                    """
                    SELECT id
                    FROM users
                    WHERE email = ?
                    AND id != ?
                    """,
                    (
                        email,
                        user_id
                    )
                ).fetchone()

                if existing:

                    error = "That email address is already in use."

                else:

                    connection.execute(
                        """
                        UPDATE users
                        SET display_name = ?,
                            email = ?
                        WHERE id = ?
                        """,
                        (
                            display_name,
                            email,
                            user_id
                        )
                    )

                    connection.commit()

                    session["display_name"] = display_name

                    success = "Profile updated successfully."

        # ----------------------------------------------------
        # PROFILE PHOTO
        # ----------------------------------------------------

        elif action == "profile_photo":

            photo = request.files.get(
                "profile_photo"
            )

            if photo is None or not photo.filename:

                error = "Please choose a profile image."

            else:

                allowed_photo_types = {
                    "image/png": "PNG",
                    "image/jpeg": "JPEG",
                    "image/webp": "WEBP"
                }

                mimetype = (
                    photo.mimetype or ""
                ).lower()

                if mimetype not in allowed_photo_types:

                    error = (
                        "Use a PNG, JPG/JPEG, or WEBP profile image."
                    )

                else:

                    photo_bytes = photo.read()

                    if not photo_bytes:

                        error = "The selected profile image is empty."

                    elif len(photo_bytes) > 2 * 1024 * 1024:

                        error = (
                            "Profile image must be 2 MB or smaller."
                        )

                    else:

                        connection.execute(
                            """
                            UPDATE users
                            SET profile_photo = ?,
                                profile_photo_mimetype = ?
                            WHERE id = ?
                            """,
                            (
                                sqlite3.Binary(photo_bytes),
                                mimetype,
                                user_id
                            )
                        )

                        connection.commit()

                        success = "Profile photo updated successfully."

        # ----------------------------------------------------
        # CHANGE PASSWORD
        # ----------------------------------------------------

        elif action == "change_password":

            if user["google_id"]:

                error = (
                    "Google accounts do not use a QRGuard password. "
                    "Use Google to manage your account security."
                )

            elif not user["password_hash"]:

                error = "Password change is not available for this account."

            else:

                current_password = request.form.get(
                    "current_password",
                    ""
                )

                new_password = request.form.get(
                    "new_password",
                    ""
                )

                confirm_password = request.form.get(
                    "confirm_password",
                    ""
                )

                if not check_password_hash(
                    user["password_hash"],
                    current_password
                ):

                    error = "Current password is incorrect."

                elif len(new_password) < 6:

                    error = (
                        "New password must contain at least 6 characters."
                    )

                elif new_password != confirm_password:

                    error = "New passwords do not match."

                elif new_password == current_password:

                    error = (
                        "New password must be different from the current password."
                    )

                else:

                    connection.execute(
                        """
                        UPDATE users
                        SET password_hash = ?,
                            password_salt = ?
                        WHERE id = ?
                        """,
                        (
                            generate_password_hash(new_password),
                            secrets.token_hex(16),
                            user_id
                        )
                    )

                    connection.commit()

                    success = "Password changed successfully."

        else:

            error = "Invalid profile action."

        connection.close()

    connection = get_db()

    user = connection.execute(
        """
        SELECT
            id,
            username,
            email,
            password_hash,
            google_id,
            display_name,
            profile_photo,
            profile_photo_mimetype,
            created_at
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    connection.close()

    if user is None:

        session.clear()

        return redirect(
            url_for("login")
        )

    account_type = (
        "Google"
        if user["google_id"]
        else "Local"
    )

    return render_template(
        "profile.html",
        user=user,
        account_type=account_type,
        error=error,
        success=success
    )


# ============================================================
# PROFILE PHOTO
# ============================================================

@app.route("/profile/photo")
@login_required
def profile_photo():

    user_id = session["user_id"]

    connection = get_db()

    user = connection.execute(
        """
        SELECT
            profile_photo,
            profile_photo_mimetype
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    connection.close()

    if not user or not user["profile_photo"]:

        return "", 404

    return send_file(
        io.BytesIO(user["profile_photo"]),
        mimetype=(
            user["profile_photo_mimetype"]
            or "image/png"
        ),
        max_age=300
    )


# ============================================================
# DELETE PROFILE PHOTO
# ============================================================

@app.route(
    "/profile/photo/delete",
    methods=["POST"]
)
@login_required
def delete_profile_photo():

    connection = get_db()

    connection.execute(
        """
        UPDATE users
        SET profile_photo = NULL,
            profile_photo_mimetype = NULL
        WHERE id = ?
        """,
        (session["user_id"],)
    )

    connection.commit()
    connection.close()

    return redirect(
        url_for("profile")
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
# MAIN PAGE
# ============================================================

@app.route("/")
@login_required
def index():

    return render_template(
        "index.html"
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

    try:

        if "qr_image" not in request.files:

            return render_template(
                "index.html",
                error="Please select a QR image."
            )

        file = request.files[
            "qr_image"
        ]

        if file.filename == "":

            return render_template(
                "index.html",
                error=(
                    "No file selected. "
                    "Please choose a QR image."
                )
            )

        allowed_extensions = {
            "png",
            "jpg",
            "jpeg",
            "webp",
            "bmp"
        }

        filename = file.filename.lower()

        if (
            "."
            not in filename
            or filename.rsplit(
                ".",
                1
            )[1]
            not in allowed_extensions
        ):

            return render_template(
                "index.html",
                error=(
                    "Unsupported image format."
                )
            )

        image_bytes = file.read()

        if not image_bytes:

            return render_template(
                "index.html",
                error="Uploaded image is empty."
            )

        if len(image_bytes) > 5 * 1024 * 1024:

            return render_template(
                "index.html",
                error=(
                    "File is too large. "
                    "Maximum allowed size is 5 MB."
                )
            )

        numpy_array = np.frombuffer(
            image_bytes,
            dtype=np.uint8
        )

        image = cv2.imdecode(
            numpy_array,
            cv2.IMREAD_COLOR
        )

        if image is None:

            return render_template(
                "index.html",
                error=(
                    "Unable to read the uploaded image."
                )
            )

        detector = cv2.QRCodeDetector()

        data, points, _ = (
            detector.detectAndDecode(
                image
            )
        )

        if not data:

            return render_template(
                "index.html",
                error=(
                    "No readable QR code was detected. "
                    "Please upload a clear QR image."
                )
            )

        url = data.strip()

        valid, validation_error = (
            validate_url(url)
        )

        if not valid:

            return render_template(
                "index.html",
                error=validation_error
            )

        analysis = combined_analysis(
            url
        )

        user_id = session[
            "user_id"
        ]

        scan_id = save_scan(
            user_id,
            url,
            analysis["score"],
            analysis["risk"],
            analysis["ml_prediction"],
            analysis["ml_confidence"],
            analysis["ml_score"]
        )

        result = {

            "id":
                scan_id,

            "url":
                url,

            "score":
                analysis["score"],

            "risk":
                analysis["risk"],

            "reasons":
                analysis["reasons"],

            "details":
                analysis["details"],

            "ml_prediction":
                analysis["ml_prediction"],

            "ml_confidence":
                analysis["ml_confidence"],

            "ml_score":
                analysis["ml_score"],

            "rule_score":
                analysis["rule_score"]
        }

        return render_template(
            "result.html",
            result=result
        )

    except cv2.error:

        return render_template(
            "index.html",
            error=(
                "The image could not be processed."
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
                "Database error occurred."
            )
        )

    except Exception as exception:

        print(
            "QRGuard Error:",
            exception
        )

        return render_template(
            "index.html",
            error=(
                "An unexpected error occurred "
                "while processing the QR image."
            )
        )


# ============================================================
# HISTORY
# ============================================================

@app.route("/history")
@login_required
def history():

    connection = get_db()

    scans = connection.execute(
        """
        SELECT
            id,
            url,
            score,
            risk,
            ml_prediction,
            ml_confidence,
            ml_score,
            scanned_at
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (
            session["user_id"],
        )
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

    connection = get_db()

    user_id = session[
        "user_id"
    ]

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

    ml_phishing = connection.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE user_id = ?
        AND ml_prediction = ?
        """,
        (
            user_id,
            "Potential Phishing"
        )
    ).fetchone()[0]

    recent_scans = connection.execute(
        """
        SELECT
            id,
            url,
            score,
            risk,
            ml_prediction,
            ml_confidence,
            ml_score,
            scanned_at
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 5
        """,
        (
            user_id,
        )
    ).fetchall()

    connection.close()

    stats = {

        "total":
            total,

        "low":
            low,

        "medium":
            medium,

        "high":
            high,

        "ml_phishing":
            ml_phishing
    }

    return render_template(
        "dashboard.html",
        stats=stats,
        recent_scans=recent_scans
    )


# ============================================================
# PREMIUM PDF REPORT
# ============================================================

@app.route(
    "/report/<int:scan_id>"
)
@login_required
def report(scan_id):

    connection = get_db()

    scan = connection.execute(
        """
        SELECT
            id,
            url,
            score,
            risk,
            ml_prediction,
            ml_confidence,
            ml_score,
            scanned_at
        FROM scans
        WHERE id = ?
        AND user_id = ?
        """,
        (
            scan_id,
            session["user_id"]
        )
    ).fetchone()

    connection.close()

    if scan is None:

        return (
            "Scan record not found.",
            404
        )

    url = scan["url"]

    score = (
        scan["score"]
        if scan["score"] is not None
        else 0
    )

    risk = (
        scan["risk"]
        or "UNKNOWN"
    )

    ml_prediction = (
        scan["ml_prediction"]
        or "Not available"
    )

    ml_confidence = (
        scan["ml_confidence"]
        if scan["ml_confidence"] is not None
        else 0
    )

    ml_score = (
        scan["ml_score"]
        if scan["ml_score"] is not None
        else 0
    )

    scanned_at = (
        scan["scanned_at"]
    )

    rule_score, _, rule_reasons, rule_details = (
        analyze_url(url)
    )

    rule_contribution = round(
        rule_score * 0.70,
        1
    )

    ml_contribution = round(
        ml_score * 0.30,
        1
    )

    pdf_buffer = io.BytesIO()

    document = SimpleDocTemplate(
        pdf_buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=15 * mm,
        bottomMargin=18 * mm,
        title="QRGuard Security Analysis Report",
        author="QRGuard",
        subject="QR-Code Phishing Detection Security Report"
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "QRTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=25,
        leading=29,
        textColor=colors.HexColor("#0b2239"),
        spaceAfter=3
    )

    subtitle_style = ParagraphStyle(
        "QRSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#666666"),
        spaceAfter=10
    )

    section_style = ParagraphStyle(
        "QRSection",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0b2239"),
        spaceBefore=9,
        spaceAfter=7
    )

    normal_style = ParagraphStyle(
        "QRNormal",
        parent=styles["Normal"],
        fontSize=8.8,
        leading=12.5,
        textColor=colors.HexColor("#222222")
    )

    small_style = ParagraphStyle(
        "QRSmall",
        parent=styles["Normal"],
        fontSize=7.8,
        leading=10.5,
        textColor=colors.HexColor("#333333")
    )

    white_center_style = ParagraphStyle(
        "QRWhiteCenter",
        parent=styles["Normal"],
        fontSize=8.8,
        leading=12,
        textColor=colors.white,
        alignment=TA_CENTER
    )

    white_large_style = ParagraphStyle(
        "QRWhiteLarge",
        parent=styles["Normal"],
        fontSize=15,
        leading=18,
        textColor=colors.white,
        alignment=TA_CENTER
    )

    center_style = ParagraphStyle(
        "QRCenter",
        parent=normal_style,
        alignment=TA_CENTER
    )

    right_style = ParagraphStyle(
        "QRRight",
        parent=small_style,
        alignment=TA_RIGHT
    )

    story = []

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
                    white_center_style
                )
            ]
        ],
        colWidths=[
            178 * mm
        ],
        rowHeights=[
            13 * mm
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
                "BOX",
                (0, 0),
                (-1, -1),
                1,
                colors.HexColor("#c9a227")
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),
            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER"
            )
        ])
    )

    story.append(
        header_table
    )

    story.append(
        Spacer(1, 9)
    )

    story.append(
        Paragraph(
            "1. Scan Summary",
            section_style
        )
    )

    safe_url = html.escape(
        url
    )

    summary_table = Table(
        [
            [
                Paragraph(
                    "<b>Scan ID</b>",
                    small_style
                ),
                str(scan["id"])
            ],
            [
                Paragraph(
                    "<b>Scanned URL</b>",
                    small_style
                ),
                Paragraph(
                    safe_url,
                    small_style
                )
            ],
            [
                Paragraph(
                    "<b>Scanned At</b>",
                    small_style
                ),
                str(scanned_at)
            ],
            [
                Paragraph(
                    "<b>Analysis Type</b>",
                    small_style
                ),
                "Static QR URL Security Analysis"
            ]
        ],
        colWidths=[
            42 * mm,
            136 * mm
        ]
    )

    summary_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#b7c1ca")
            ),
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#edf2f7")
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
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(
        summary_table
    )

    story.append(
        Spacer(1, 9)
    )

    story.append(
        Paragraph(
            "2. Final Risk Assessment",
            section_style
        )
    )

    if risk == "LOW RISK":

        risk_color = colors.HexColor(
            "#198754"
        )

        risk_message = (
            "The URL contains relatively few suspicious indicators "
            "under the current QRGuard analysis rules."
        )

    elif risk == "MEDIUM RISK":

        risk_color = colors.HexColor(
            "#d39e00"
        )

        risk_message = (
            "The URL contains several indicators that require "
            "additional verification before interaction."
        )

    else:

        risk_color = colors.HexColor(
            "#dc3545"
        )

        risk_message = (
            "The URL contains multiple suspicious indicators "
            "and should be treated with caution."
        )

    bar_width = 178 * mm

    filled_width = max(
        2 * mm,
        bar_width * (
            max(
                0,
                min(
                    score,
                    100
                )
            ) / 100
        )
    )

    remaining_width = max(
        1 * mm,
        bar_width - filled_width
    )

    score_bar = Table(
        [
            ["", ""]
        ],
        colWidths=[
            filled_width,
            remaining_width
        ],
        rowHeights=[
            6 * mm
        ]
    )

    score_bar.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, 0),
                risk_color
            ),
            (
                "BACKGROUND",
                (1, 0),
                (1, 0),
                colors.HexColor("#e9ecef")
            ),
            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#adb5bd")
            )
        ])
    )

    story.append(
        score_bar
    )

    story.append(
        Spacer(1, 5)
    )

    risk_table = Table(
        [
            [
                Paragraph(
                    "<b>FINAL SCORE</b><br/>"
                    f"<font size='26'>{score}/100</font>",
                    ParagraphStyle(
                        "FinalScore",
                        parent=normal_style,
                        alignment=TA_CENTER,
                        leading=30
                    )
                ),
                Paragraph(
                    "<b>RISK LEVEL</b><br/>"
                    f"<font size='15'>{html.escape(risk)}</font>",
                    white_large_style
                )
            ]
        ],
        colWidths=[
            89 * mm,
            89 * mm
        ],
        rowHeights=[
            24 * mm
        ]
    )

    risk_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, 0),
                colors.HexColor("#f1f4f7")
            ),
            (
                "BACKGROUND",
                (1, 0),
                (1, 0),
                risk_color
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),
            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER"
            ),
            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.7,
                colors.HexColor("#9aa4ad")
            )
        ])
    )

    story.append(
        risk_table
    )

    story.append(
        Spacer(1, 6)
    )

    story.append(
        Paragraph(
            html.escape(
                risk_message
            ),
            normal_style
        )
    )

    story.append(
        Spacer(1, 8)
    )

    story.append(
        Paragraph(
            "3. Score Breakdown",
            section_style
        )
    )

    score_table = Table(
        [
            [
                Paragraph(
                    "<b>Component</b>",
                    white_center_style
                ),
                Paragraph(
                    "<b>Score</b>",
                    white_center_style
                ),
                Paragraph(
                    "<b>Weight</b>",
                    white_center_style
                ),
                Paragraph(
                    "<b>Contribution</b>",
                    white_center_style
                )
            ],
            [
                "Rule-Based Analysis",
                f"{rule_score}/100",
                "70%",
                f"{rule_contribution}"
            ],
            [
                "Machine Learning",
                f"{ml_score}/100",
                "30%",
                f"{ml_contribution}"
            ],
            [
                Paragraph(
                    "<b>Final QRGuard Score</b>",
                    small_style
                ),
                Paragraph(
                    f"<b>{score}/100</b>",
                    center_style
                ),
                "100%",
                Paragraph(
                    f"<b>{score}</b>",
                    center_style
                )
            ]
        ],
        colWidths=[
            68 * mm,
            31 * mm,
            30 * mm,
            49 * mm
        ]
    )

    score_table.setStyle(
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
                "BACKGROUND",
                (0, -1),
                (-1, -1),
                colors.HexColor("#eaf2f8")
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#adb5bd")
            ),
            (
                "ALIGN",
                (1, 1),
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
        score_table
    )

    story.append(
        Spacer(1, 9)
    )

    story.append(
        Paragraph(
            "4. Machine Learning Analysis",
            section_style
        )
    )

    ml_prediction_safe = html.escape(
        str(ml_prediction)
    )

    ml_table = Table(
        [
            [
                Paragraph(
                    "<b>ML PREDICTION</b><br/><br/>"
                    f"<font size='13'>{ml_prediction_safe}</font>",
                    ParagraphStyle(
                        "MLPrediction",
                        parent=normal_style,
                        alignment=TA_CENTER,
                        leading=17
                    )
                ),
                Paragraph(
                    "<b>CONFIDENCE</b><br/><br/>"
                    f"<font size='18'>{float(ml_confidence):.1f}%</font>",
                    ParagraphStyle(
                        "MLConfidence",
                        parent=normal_style,
                        alignment=TA_CENTER,
                        leading=22
                    )
                ),
                Paragraph(
                    "<b>PHISHING SCORE</b><br/><br/>"
                    f"<font size='18'>{ml_score}/100</font>",
                    ParagraphStyle(
                        "MLScore",
                        parent=normal_style,
                        alignment=TA_CENTER,
                        leading=22
                    )
                )
            ]
        ],
        colWidths=[
            78 * mm,
            50 * mm,
            50 * mm
        ],
        rowHeights=[
            27 * mm
        ]
    )

    ml_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor("#f4f0fa")
            ),
            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.8,
                colors.HexColor("#6f42c1")
            ),
            (
                "INNERGRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#c8b8dd")
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            )
        ])
    )

    story.append(
        ml_table
    )

    story.append(
        Spacer(1, 7)
    )

    story.append(
        Paragraph(
            "The Random Forest classifier evaluates extracted URL "
            "features and produces a phishing probability score. "
            "The ML phishing score contributes 30% to the final "
            "QRGuard score.",
            normal_style
        )
    )

    story.append(
        Spacer(1, 9)
    )

    story.append(
        Paragraph(
            "5. Detection Indicators",
            section_style
        )
    )

    indicator_rows = [
        [
            Paragraph(
                "<b>Indicator</b>",
                white_center_style
            ),
            Paragraph(
                "<b>Points</b>",
                white_center_style
            )
        ]
    ]

    for detail in rule_details:

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
                Paragraph(
                    str(
                        detail["points"]
                    ),
                    ParagraphStyle(
                        "IndicatorPoints",
                        parent=small_style,
                        alignment=TA_CENTER
                    )
                )
            ]
        )

    indicator_rows.append(
        [
            Paragraph(
                html.escape(
                    "ML prediction: "
                    + str(ml_prediction)
                    + " ("
                    + f"{float(ml_confidence):.1f}"
                    + "% confidence)"
                ),
                small_style
            ),
            Paragraph(
                str(ml_score),
                ParagraphStyle(
                    "MLIndicatorPoints",
                    parent=small_style,
                    alignment=TA_CENTER
                )
            )
        ]
    )

    indicator_table = Table(
        indicator_rows,
        colWidths=[
            149 * mm,
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
                colors.HexColor("#adb5bd")
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
                5
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                5
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
            (
                "RIGHTPADDING",
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
        Spacer(1, 9)
    )

    story.append(
        Paragraph(
            "6. Risk Classification",
            section_style
        )
    )

    classification_table = Table(
        [
            [
                Paragraph(
                    "<b>Score Range</b>",
                    white_center_style
                ),
                Paragraph(
                    "<b>Classification</b>",
                    white_center_style
                )
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
            80 * mm,
            98 * mm
        ]
    )

    classification_table.setStyle(
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
                "BACKGROUND",
                (0, 1),
                (-1, 1),
                colors.HexColor("#e8f5e9")
            ),
            (
                "BACKGROUND",
                (0, 2),
                (-1, 2),
                colors.HexColor("#fff3cd")
            ),
            (
                "BACKGROUND",
                (0, 3),
                (-1, 3),
                colors.HexColor("#f8d7da")
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#adb5bd")
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
        classification_table
    )

    story.append(
        Spacer(1, 9)
    )

    story.append(
        Paragraph(
            "7. Security Methodology",
            section_style
        )
    )

    methodology = [

        "QR image is decoded locally using OpenCV.",

        "The extracted URL is validated as an HTTP/HTTPS URL.",

        "Static URL features are extracted without visiting the website.",

        "Rule-based security indicators are calculated.",

        "A Random Forest machine-learning classifier evaluates "
        "the URL feature pattern.",

        "Rule-based analysis contributes 70% to the combined score.",

        "Machine-learning analysis contributes 30% to the combined score.",

        "The final score is limited to a maximum of 100.",

        "The final score is classified into LOW, MEDIUM, or HIGH risk.",

        "The submitted URL is not automatically opened or visited "
        "by QRGuard."
    ]

    for number, item in enumerate(
        methodology,
        start=1
    ):

        story.append(
            Paragraph(
                f"<b>{number}.</b> "
                + html.escape(item),
                normal_style
            )
        )

        story.append(
            Spacer(1, 2)
        )

    story.append(
        Spacer(1, 7)
    )

    notice_table = Table(
        [
            [
                Paragraph(
                    "<b>SECURITY NOTICE</b><br/><br/>"
                    "QRGuard performs static URL analysis. "
                    "The machine-learning model is trained on a "
                    "small project dataset and is intended for "
                    "educational and defensive cybersecurity use. "
                    "A risk classification is an automated assessment "
                    "and should not be treated as absolute proof that "
                    "a website is malicious or safe.",
                    small_style
                )
            ]
        ],
        colWidths=[
            178 * mm
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
                0.8,
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
                9
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                9
            )
        ])
    )

    story.append(
        notice_table
    )

    story.append(
        Spacer(1, 9)
    )

    story.append(
        Paragraph(
            "8. Disclaimer",
            section_style
        )
    )

    disclaimer = (
        "This report is generated for educational and defensive "
        "cybersecurity analysis purposes. QRGuard uses heuristic "
        "indicators and a lightweight machine-learning model. "
        "The model may produce false positives or false negatives. "
        "Users should verify suspicious links through trusted "
        "security resources before interacting with them."
    )

    story.append(
        Paragraph(
            disclaimer,
            normal_style
        )
    )

    story.append(
        Spacer(1, 13)
    )

    footer_table = Table(
        [
            [
                Paragraph(
                    "<b>QRGuard © 2026</b>",
                    small_style
                ),
                Paragraph(
                    "Cyber Security Project",
                    right_style
                )
            ]
        ],
        colWidths=[
            89 * mm,
            89 * mm
        ]
    )

    footer_table.setStyle(
        TableStyle([
            (
                "LINEABOVE",
                (0, 0),
                (-1, 0),
                0.8,
                colors.HexColor("#c9a227")
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                6
            )
        ])
    )

    story.append(
        footer_table
    )

    def add_page_number(
        canvas,
        doc
    ):

        canvas.saveState()

        canvas.setFont(
            "Helvetica",
            7
        )

        canvas.setFillColor(
            colors.HexColor("#666666")
        )

        canvas.drawCentredString(
            A4[0] / 2,
            8 * mm,
            f"Page {doc.page}"
        )

        canvas.restoreState()

    document.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number
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
        "ml_model": "RandomForest"
    }


# ============================================================
# 404
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
# 413
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
# 500
# ============================================================

@app.errorhandler(500)
def internal_server_error(error):

    return render_template(
        "index.html",
        error=(
            "A server error occurred. "
            "Please try again."
        )
    ), 500


# ============================================================
# START APPLICATION
# ============================================================

init_db()


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
