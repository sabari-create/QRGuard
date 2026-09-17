```python
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
)

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


# =========================================================
# QRGuard - QR Code Phishing Detection System
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=BASE_DIR,
    static_folder=BASE_DIR,
    static_url_path=""
)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "qrgurad-demo-secret-key"
)


# =========================================================
# DATABASE
# =========================================================

if os.environ.get("VERCEL"):
    DB_PATH = "/tmp/qrgurad.db"
else:
    DB_PATH = os.path.join(
        BASE_DIR,
        "qrgurad.db"
    )


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

    columns = [
        row["name"]
        for row in conn.execute(
            "PRAGMA table_info(scans)"
        ).fetchall()
    ]

    if "created_at" not in columns:
        try:
            conn.execute(
                """
                ALTER TABLE scans
                ADD COLUMN created_at
                TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                """
            )
        except sqlite3.OperationalError:
            pass

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

        array = np.frombuffer(
            image_bytes,
            dtype=np.uint8
        )

        image = cv2.imdecode(
            array,
            cv2.IMREAD_COLOR
        )

        if image is None:
            return None

        detector = cv2.QRCodeDetector()

        # Normal detection
        data, points, _ = detector.detectAndDecode(image)

        if data:
            return data.strip()

        # Resize retry
        height, width = image.shape[:2]

        if width < 1200 or height < 1200:

            scale = max(
                2,
                int(1200 / max(width, height))
            )

            resized = cv2.resize(
                image,
                None,
                fx=scale,
                fy=scale,
                interpolation=cv2.INTER_CUBIC
            )

            data, points, _ = detector.detectAndDecode(
                resized
            )

            if data:
                return data.strip()

        # Grayscale retry
        gray = cv2.cvtColor(
            image,
            cv2.COLOR_BGR2GRAY
        )

        data, points, _ = detector.detectAndDecode(
            gray
        )

        if data:
            return data.strip()

        # Threshold retry
        threshold = cv2.adaptiveThreshold(
            gray,
            255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY,
            31,
            5
        )

        data, points, _ = detector.detectAndDecode(
            threshold
        )

        if data:
            return data.strip()

    except Exception:
        return None

    return None


# =========================================================
# URL VALIDATION
# =========================================================

def validate_url(url):

    try:

        parsed = urlparse(url)

        if parsed.scheme.lower() not in [
            "http",
            "https"
        ]:
            return False

        if not parsed.netloc:
            return False

        return True

    except Exception:
        return False


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

    # Rule 1
    if len(url) > 100:
        score += 15
        reasons.append(
            "URL is unusually long"
        )

    # Rule 2
    if parsed.scheme.lower() != "https":
        score += 15
        reasons.append(
            "URL does not use HTTPS"
        )

    # Rule 3
    try:

        ipaddress.ip_address(hostname)

        score += 25

        reasons.append(
            "URL uses an IP address instead of a domain name"
        )

    except ValueError:
        pass

    # Rule 4
    if parsed.username or parsed.password:

        score += 20

        reasons.append(
            "URL contains embedded username or password information"
        )

    # Rule 5
    if "@" in url:

        score += 10

        reasons.append(
            "URL contains @ symbol"
        )

    # Rule 6
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

    matched_keywords = [
        word
        for word in suspicious_keywords
        if word in url.lower()
    ]

    if matched_keywords:

        score += 10

        reasons.append(
            "URL contains security-sensitive keywords: "
            + ", ".join(matched_keywords[:5])
        )

    # Rule 7
    if hostname.count(".") >= 3:

        score += 10

        reasons.append(
            "Domain contains many subdomain levels"
        )

    # Rule 8
    if "-" in hostname:

        score += 5

        reasons.append(
            "Domain contains hyphens"
        )

    # Rule 9
    digit_count = sum(
        char.isdigit()
        for char in hostname
    )

    if digit_count >= 3:

        score += 5

        reasons.append(
            "Domain contains several numeric characters"
        )

    # Rule 10
    if len(hostname) > 30:

        score += 10

        reasons.append(
            "Hostname is unusually long"
        )

    # Rule 11
    if "%" in url or "_" in url:

        score += 5

        reasons.append(
            "URL contains encoded or unusual characters"
        )

    # Rule 12
    try:

        decoded = unquote(url)

        if decoded != url:

            score += 10

            reasons.append(
                "URL contains percent-encoded content"
            )

    except Exception:
        pass

    # Rule 13
    if len(path) > 60:

        score += 10

        reasons.append(
            "URL path is unusually long"
        )

    # Rule 14
    if query:

        parameter_count = query.count("&") + 1

        if parameter_count >= 4:

            score += 10

            reasons.append(
                "URL contains many query parameters"
            )

    # Rule 15
    dangerous_extensions = [
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".apk"
    ]

    if any(
        path.lower().endswith(ext)
        for ext in dangerous_extensions
    ):

        score += 15

        reasons.append(
            "URL path points to a potentially executable file"
        )

    # Rule 16
    if "xn--" in hostname.lower():

        score += 15

        reasons.append(
            "Domain contains punycode"
        )

    # Rule 17
    if hostname.count("-") >= 3:

        score += 10

        reasons.append(
            "Domain contains multiple hyphens"
        )

    # Rule 18
    try:

        if parsed.port is not None:

            if parsed.port not in [80, 443]:

                score += 10

                reasons.append(
                    "URL uses a non-standard port"
                )

    except ValueError:

        score += 10

        reasons.append(
            "URL contains an invalid port"
        )

    # Rule 19
    labels = hostname.split(".")

    if any(
        len(label) > 25
        for label in labels
    ):

        score += 5

        reasons.append(
            "Domain contains an unusually long label"
        )

    score = min(score, 100)

    if score <= 30:
        risk = "LOW RISK"

    elif score <= 60:
        risk = "MEDIUM RISK"

    else:
        risk = "HIGH RISK"

    if not reasons:

        reasons.append(
            "No major suspicious URL indicators were detected"
        )

    return score, risk, reasons


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

        return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template(
        "login.html"
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# HOME / SCANNER
# =========================================================

@app.route("/")
def index():

    if not session.get("logged_in"):

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

    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )

    # IMPORTANT:
    # Must match index.html:
    # name="qr_file"

    uploaded_file = request.files.get(
        "qr_file"
    )

    if (
        uploaded_file is None
        or uploaded_file.filename == ""
    ):

        return render_template(
            "index.html",
            error="Please select a QR image."
        )

    try:

        image_bytes = uploaded_file.read()

        url = decode_qr_image(
            image_bytes
        )

        if not url:

            return render_template(
                "index.html",
                error=(
                    "QR code could not be detected. "
                    "Please upload a clear QR image."
                )
            )

        if not validate_url(url):

            return render_template(
                "index.html",
                error=(
                    "QR code detected, but it does not "
                    "contain a valid HTTP/HTTPS URL."
                )
            )

        score, risk, reasons = analyze_url(
            url
        )

        conn = get_db()

        conn.execute(
            """
            INSERT INTO scans
            (url, score, risk, reasons)
            VALUES (?, ?, ?, ?)
            """,
            (
                url,
                score,
                risk,
                "\n".join(reasons)
            )
        )

        conn.commit()

        scan_id = conn.execute(
            "SELECT last_insert_rowid()"
        ).fetchone()[0]

        conn.close()

        return render_template(
            "result.html",
            url=url,
            score=score,
            risk=risk,
            reasons=reasons,
            scan_id=scan_id
        )

    except Exception:

        return render_template(
            "index.html",
            error=(
                "An error occurred while processing "
                "the QR image."
            )
        )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )

    try:

        conn = get_db()

        total = conn.execute(
            "SELECT COUNT(*) AS count FROM scans"
        ).fetchone()["count"]

        low = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM scans
            WHERE risk = 'LOW RISK'
            """
        ).fetchone()["count"]

        medium = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM scans
            WHERE risk = 'MEDIUM RISK'
            """
        ).fetchone()["count"]

        high = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM scans
            WHERE risk = 'HIGH RISK'
            """
        ).fetchone()["count"]

        recent = conn.execute(
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
            recent=recent
        )

    except Exception:

        return render_template(
            "dashboard.html",
            total=0,
            low=0,
            medium=0,
            high=0,
            recent=[]
        )


# =========================================================
# HISTORY
# =========================================================

@app.route("/history")
def history():

    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )

    try:

        conn = get_db()

        scans = conn.execute(
            """
            SELECT *
            FROM scans
            ORDER BY id DESC
            """
        ).fetchall()

        conn.close()

    except Exception:

        scans = []

    return render_template(
        "history.html",
        scans=scans
    )


# =========================================================
# PDF REPORT
# =========================================================

@app.route(
    "/report/<int:scan_id>"
)
def report(scan_id):

    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )

    conn = get_db()

    scan = conn.execute(
        """
        SELECT *
        FROM scans
        WHERE id = ?
        """,
        (scan_id,)
    ).fetchone()

    conn.close()

    if scan is None:

        return "Scan not found", 404

    buffer = io.BytesIO()

    pdf = canvas.Canvas(
        buffer,
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
        "QRGuard Security Report"
    )

    y -= 40

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
        f"Risk Level: {scan['risk']}"
    )

    y -= 22

    pdf.drawString(
        50,
        y,
        f"Risk Score: {scan['score']}/100"
    )

    y -= 30

    pdf.setFont(
        "Helvetica-Bold",
        11
    )

    pdf.drawString(
        50,
        y,
        "Detected URL:"
    )

    y -= 20

    pdf.setFont(
        "Helvetica",
        9
    )

    url_text = scan["url"]

    while len(url_text) > 90:

        if y < 60:

            pdf.showPage()

            y = height - 60

        pdf.drawString(
            50,
            y,
            url_text[:90]
        )

        url_text = url_text[90:]

        y -= 14

    pdf.drawString(
        50,
        y,
        url_text
    )

    y -= 30

    pdf.setFont(
        "Helvetica-Bold",
        11
    )

    pdf.drawString(
        50,
        y,
        "Security Analysis:"
    )

    y -= 20

    pdf.setFont(
        "Helvetica",
        9
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
                9
            )

        pdf.drawString(
            60,
            y,
            "- " + reason[:110]
        )

        y -= 16

    y -= 20

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
        y - 14,
        "It does not automatically open or visit the detected URL."
    )

    pdf.save()

    buffer.seek(0)

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=(
            f"qrgurad_report_{scan_id}.pdf"
        )
    )


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/health")
def health():

    return {
        "status": "ok",
        "application": "QRGuard"
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
```
