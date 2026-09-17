import os
import io
import sqlite3
import ipaddress
from urllib.parse import urlparse, unquote

import cv2
import numpy as np

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_file,
    flash
)

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "qrgurad-secret-key")


# =========================================================
# PATHS
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

if os.environ.get("VERCEL"):
    DB_PATH = "/tmp/qrgurad.db"
else:
    DB_PATH = os.path.join(BASE_DIR, "qrgurad.db")


# =========================================================
# DATABASE
# =========================================================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            risk TEXT NOT NULL,
            reasons TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    columns = conn.execute(
        "PRAGMA table_info(scans)"
    ).fetchall()

    column_names = [column["name"] for column in columns]

    if "created_at" not in column_names:
        conn.execute(
            "ALTER TABLE scans ADD COLUMN created_at TIMESTAMP"
        )

        conn.execute("""
            UPDATE scans
            SET created_at = CURRENT_TIMESTAMP
            WHERE created_at IS NULL
        """)

    conn.commit()
    conn.close()


init_db()


# =========================================================
# QR CODE DECODER
# =========================================================

def decode_qr_image(image_bytes):

    if not image_bytes:
        return None

    try:

        np_data = np.frombuffer(
            image_bytes,
            np.uint8
        )

        image = cv2.imdecode(
            np_data,
            cv2.IMREAD_COLOR
        )

        if image is None:
            return None

        detector = cv2.QRCodeDetector()

        # Attempt 1
        data, points, _ = detector.detectAndDecode(image)

        if data:
            return data.strip()

        # Attempt 2 - resize
        height, width = image.shape[:2]

        if width > 0 and height > 0:

            resized = cv2.resize(
                image,
                None,
                fx=2,
                fy=2,
                interpolation=cv2.INTER_CUBIC
            )

            data, points, _ = detector.detectAndDecode(
                resized
            )

            if data:
                return data.strip()

        # Attempt 3 - grayscale
        gray = cv2.cvtColor(
            image,
            cv2.COLOR_BGR2GRAY
        )

        data, points, _ = detector.detectAndDecode(
            gray
        )

        if data:
            return data.strip()

        # Attempt 4 - adaptive threshold
        threshold = cv2.adaptiveThreshold(
            gray,
            255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY,
            11,
            2
        )

        data, points, _ = detector.detectAndDecode(
            threshold
        )

        if data:
            return data.strip()

        return None

    except Exception as e:

        print("QR Decode Error:", e)

        return None


# =========================================================
# URL VALIDATION
# =========================================================

def validate_url(url):

    if not url:
        return False

    url = url.strip()

    if len(url) > 2048:
        return False

    parsed = urlparse(url)

    if parsed.scheme not in (
        "http",
        "https"
    ):
        return False

    if not parsed.netloc:
        return False

    return True


# =========================================================
# URL RISK ANALYSIS
# =========================================================

def analyze_url(url):

    score = 0
    reasons = []

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # 1. Long URL
    if len(url) > 100:

        score += 15

        reasons.append(
            "URL is unusually long."
        )

    # 2. HTTP
    if parsed.scheme.lower() != "https":

        score += 15

        reasons.append(
            "URL does not use HTTPS."
        )

    # 3. IP address
    try:

        ipaddress.ip_address(hostname)

        score += 25

        reasons.append(
            "URL uses an IP address instead of a normal domain name."
        )

    except ValueError:
        pass

    # 4. Username/password
    if parsed.username or parsed.password:

        score += 20

        reasons.append(
            "URL contains embedded username or password information."
        )

    # 5. @ symbol
    if "@" in url:

        score += 10

        reasons.append(
            "URL contains '@', which can be used to disguise the real host."
        )

    # 6. Suspicious keywords
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

    lower_url = url.lower()

    found_keywords = []

    for keyword in suspicious_keywords:

        if keyword in lower_url:
            found_keywords.append(keyword)

    if found_keywords:

        score += 10

        reasons.append(
            "URL contains suspicious security/account-related keywords."
        )

    # 7. Many subdomains
    if hostname.count(".") >= 3:

        score += 10

        reasons.append(
            "Hostname contains many subdomains."
        )

    # 8. Hyphen
    if "-" in hostname:

        score += 5

        reasons.append(
            "Hostname contains hyphens."
        )

    # 9. Digits
    digit_count = sum(
        char.isdigit()
        for char in hostname
    )

    if digit_count >= 3:

        score += 5

        reasons.append(
            "Hostname contains several digits."
        )

    # 10. Long hostname
    if len(hostname) > 30:

        score += 10

        reasons.append(
            "Hostname is unusually long."
        )

    # 11. Special characters
    if "%" in url or "_" in hostname:

        score += 5

        reasons.append(
            "URL contains unusual encoding or hostname characters."
        )

    # 12. URL encoding
    try:

        decoded_url = unquote(url)

        if decoded_url != url:

            score += 10

            reasons.append(
                "URL contains encoded characters."
            )

    except Exception:
        pass

    # 13. Long path
    if len(path) > 60:

        score += 10

        reasons.append(
            "URL path is unusually long."
        )

    # 14. Query parameters
    if query:

        parameter_count = query.count("&") + 1

        if parameter_count >= 4:

            score += 10

            reasons.append(
                "URL contains many query parameters."
            )

    # 15. Dangerous file extensions
    dangerous_extensions = (
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".apk"
    )

    if path.lower().endswith(
        dangerous_extensions
    ):

        score += 15

        reasons.append(
            "URL points to a potentially dangerous executable file type."
        )

    # 16. Punycode
    if "xn--" in hostname.lower():

        score += 15

        reasons.append(
            "Hostname uses Punycode/IDN encoding."
        )

    # 17. Multiple hyphens
    if hostname.count("-") >= 3:

        score += 10

        reasons.append(
            "Hostname contains multiple hyphens."
        )

    # 18. Non-standard port
    try:

        port = parsed.port

        if port and port not in (
            80,
            443
        ):

            score += 10

            reasons.append(
                "URL uses a non-standard network port."
            )

    except ValueError:

        score += 10

        reasons.append(
            "URL contains an invalid port value."
        )

    # 19. Long hostname label
    labels = hostname.split(".")

    for label in labels:

        if len(label) > 25:

            score += 5

            reasons.append(
                "Hostname contains an unusually long domain label."
            )

            break

    # Limit score
    score = min(score, 100)

    # Risk classification
    if score <= 30:

        risk = "LOW RISK"

    elif score <= 60:

        risk = "MEDIUM RISK"

    else:

        risk = "HIGH RISK"

    reasons = list(
        dict.fromkeys(reasons)
    )

    if not reasons:

        reasons.append(
            "No major suspicious URL characteristics were detected."
        )

    return score, risk, reasons


# =========================================================
# SAVE SCAN
# =========================================================

def save_scan(
    url,
    score,
    risk,
    reasons
):

    conn = get_db()

    conn.execute(
        """
        INSERT INTO scans
        (url, score, risk, reasons, created_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (
            url,
            score,
            risk,
            "\n".join(reasons)
        )
    )

    conn.commit()
    conn.close()


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if (
            username == "admin"
            and password == "qrgurad123"
        ):

            session["logged_in"] = True

            return redirect(
                url_for("index")
            )

        flash(
            "Invalid username or password."
        )

    return render_template(
        "login.html"
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


def require_login():

    return session.get(
        "logged_in"
    ) is True


# =========================================================
# HOME
# =========================================================

@app.route("/")
def index():

    if not require_login():

        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html"
    )


# =========================================================
# QR SCAN
# =========================================================

@app.route(
    "/scan",
    methods=["POST"]
)
def scan():

    if not require_login():

        return redirect(
            url_for("login")
        )

    uploaded_file = request.files.get(
        "qr_image"
    )

    if not uploaded_file:

        flash(
            "Please select a QR image."
        )

        return redirect(
            url_for("index")
        )

    try:

        image_bytes = uploaded_file.read()

        if not image_bytes:

            flash(
                "Uploaded image is empty."
            )

            return redirect(
                url_for("index")
            )

        url = decode_qr_image(
            image_bytes
        )

        if not url:

            flash(
                "QR code could not be detected. "
                "Try a clear PNG/JPG image."
            )

            return redirect(
                url_for("index")
            )

        if not validate_url(url):

            flash(
                "QR code was detected, but it does not contain "
                "a valid HTTP/HTTPS URL."
            )

            return redirect(
                url_for("index")
            )

        score, risk, reasons = analyze_url(
            url
        )

        save_scan(
            url,
            score,
            risk,
            reasons
        )

        return render_template(
            "result.html",
            url=url,
            score=score,
            risk=risk,
            reasons=reasons
        )

    except Exception as e:

        print(
            "Scan Error:",
            e
        )

        flash(
            "An error occurred while processing the QR image."
        )

        return redirect(
            url_for("index")
        )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if not require_login():

        return redirect(
            url_for("login")
        )

    conn = get_db()

    total = conn.execute(
        "SELECT COUNT(*) AS count FROM scans"
    ).fetchone()["count"]

    low = conn.execute(
        "SELECT COUNT(*) AS count FROM scans "
        "WHERE risk = 'LOW RISK'"
    ).fetchone()["count"]

    medium = conn.execute(
        "SELECT COUNT(*) AS count FROM scans "
        "WHERE risk = 'MEDIUM RISK'"
    ).fetchone()["count"]

    high = conn.execute(
        "SELECT COUNT(*) AS count FROM scans "
        "WHERE risk = 'HIGH RISK'"
    ).fetchone()["count"]

    recent_scans = conn.execute(
        """
        SELECT *
        FROM scans
        ORDER BY id DESC
        LIMIT 10
        """
    ).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        total=total,
        low=low,
        medium=medium,
        high=high,
        recent_scans=recent_scans
    )


# =========================================================
# HISTORY
# =========================================================

@app.route("/history")
def history():

    if not require_login():

        return redirect(
            url_for("login")
        )

    search = request.args.get(
        "search",
        ""
    ).strip()

    risk_filter = request.args.get(
        "risk",
        ""
    ).strip()

    conn = get_db()

    query = """
        SELECT *
        FROM scans
        WHERE 1=1
    """

    params = []

    if search:

        query += " AND url LIKE ?"

        params.append(
            "%" + search + "%"
        )

    if risk_filter in (
        "LOW RISK",
        "MEDIUM RISK",
        "HIGH RISK"
    ):

        query += " AND risk = ?"

        params.append(
            risk_filter
        )

    query += " ORDER BY id DESC"

    scans = conn.execute(
        query,
        params
    ).fetchall()

    total = conn.execute(
        "SELECT COUNT(*) AS count FROM scans"
    ).fetchone()["count"]

    low = conn.execute(
        "SELECT COUNT(*) AS count FROM scans "
        "WHERE risk='LOW RISK'"
    ).fetchone()["count"]

    medium = conn.execute(
        "SELECT COUNT(*) AS count FROM scans "
        "WHERE risk='MEDIUM RISK'"
    ).fetchone()["count"]

    high = conn.execute(
        "SELECT COUNT(*) AS count FROM scans "
        "WHERE risk='HIGH RISK'"
    ).fetchone()["count"]

    conn.close()

    return render_template(
        "history.html",
        scans=scans,
        total=total,
        low=low,
        medium=medium,
        high=high,
        search=search,
        risk_filter=risk_filter
    )


# =========================================================
# PDF REPORT
# =========================================================

@app.route(
    "/report/<int:scan_id>"
)
def report(scan_id):

    if not require_login():

        return redirect(
            url_for("login")
        )

    conn = get_db()

    scan = conn.execute(
        "SELECT * FROM scans WHERE id = ?",
        (scan_id,)
    ).fetchone()

    conn.close()

    if not scan:

        flash(
            "Scan record not found."
        )

        return redirect(
            url_for("history")
        )

    pdf_buffer = io.BytesIO()

    pdf = canvas.Canvas(
        pdf_buffer,
        pagesize=A4
    )

    width, height = A4

    y = height - 60

    pdf.setFont(
        "Helvetica-Bold",
        20
    )

    pdf.drawString(
        50,
        y,
        "QRGuard - QR Code Security Report"
    )

    y -= 45

    pdf.setFont(
        "Helvetica",
        11
    )

    pdf.drawString(
        50,
        y,
        f"Scan ID: {scan['id']}"
    )

    y -= 22

    pdf.drawString(
        50,
        y,
        f"Date: {scan['created_at']}"
    )

    y -= 35

    pdf.setFont(
        "Helvetica-Bold",
        12
    )

    pdf.drawString(
        50,
        y,
        "Detected URL:"
    )

    y -= 22

    pdf.setFont(
        "Helvetica",
        10
    )

    url_text = scan["url"]

    max_chars = 90

    for i in range(
        0,
        len(url_text),
        max_chars
    ):

        pdf.drawString(
            50,
            y,
            url_text[
                i:i + max_chars
            ]
        )

        y -= 16

    y -= 15

    pdf.setFont(
        "Helvetica-Bold",
        12
    )

    pdf.drawString(
        50,
        y,
        f"Risk Score: {scan['score']}/100"
    )

    y -= 25

    pdf.drawString(
        50,
        y,
        f"Risk Level: {scan['risk']}"
    )

    y -= 35

    pdf.drawString(
        50,
        y,
        "Analysis Findings:"
    )

    y -= 22

    pdf.setFont(
        "Helvetica",
        10
    )

    reasons = (
        scan["reasons"] or ""
    ).split("\n")

    for reason in reasons:

        if y < 60:

            pdf.showPage()

            y = height - 60

            pdf.setFont(
                "Helvetica",
                10
            )

        pdf.drawString(
            60,
            y,
            "- " + reason
        )

        y -= 18

    y -= 25

    pdf.setFont(
        "Helvetica-Oblique",
        9
    )

    pdf.drawString(
        50,
        y,
        "QRGuard performs rule-based URL security analysis."
    )

    pdf.drawString(
        50,
        y - 15,
        "The system does not automatically open or visit the detected URL."
    )

    pdf.save()

    pdf_buffer.seek(0)

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f"QRGuard_Report_{scan_id}.pdf",
        mimetype="application/pdf"
    )


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/health")
def health():

    return {
        "status": "ok",
        "application": "QRGuard",
        "version": "1.0"
    }


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
