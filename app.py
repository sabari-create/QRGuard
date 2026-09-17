import os
import io
import re
import sqlite3

import cv2
import numpy as np
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_file
)


# =========================================================
# QRGuard Flask Application
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=BASE_DIR,
    static_folder=BASE_DIR,
    static_url_path=""
)

app.secret_key = "qrgurad-secret-key"


# =========================================================
# DATABASE
# =========================================================

if os.environ.get("VERCEL"):
    DB_PATH = "/tmp/qrgurad.db"
else:
    DB_PATH = os.path.join(BASE_DIR, "qrgurad.db")


def init_db():

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            risk_level TEXT,
            score INTEGER,
            reasons TEXT
        )
    """)

    conn.commit()
    conn.close()


init_db()


# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_url(url):

    score = 0
    reasons = []

    url_lower = url.lower()

    # HTTP check
    if url_lower.startswith("http://"):

        score += 15

        reasons.append(
            "URL is using HTTP instead of HTTPS."
        )

    # IP address check
    ip_pattern = r"https?://(?:\d{1,3}\.){3}\d{1,3}"

    if re.search(ip_pattern, url_lower):

        score += 25

        reasons.append(
            "URL uses an IP address instead of a domain name."
        )

    # Suspicious keywords
    suspicious_words = [
        "login",
        "verify",
        "verification",
        "account",
        "secure",
        "update",
        "password",
        "bank",
        "wallet",
        "confirm"
    ]

    found_words = []

    for word in suspicious_words:

        if word in url_lower:

            found_words.append(word)

    if found_words:

        score += min(
            len(found_words) * 5,
            25
        )

        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(found_words)
        )

    # Long URL
    if len(url) > 100:

        score += 10

        reasons.append(
            "URL is unusually long."
        )

    # @ symbol
    if "@" in url:

        score += 20

        reasons.append(
            "URL contains '@', which can hide the real destination."
        )

    # Multiple subdomains
    try:

        domain_part = (
            url.split("://", 1)[1]
            .split("/", 1)[0]
        )

        if domain_part.count(".") >= 3:

            score += 10

            reasons.append(
                "URL contains multiple subdomains."
            )

    except Exception:

        pass

    # Limit score
    score = min(score, 100)

    # Risk level
    if score >= 50:

        risk_level = "HIGH"

    elif score >= 25:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    if not reasons:

        reasons.append(
            "No major suspicious URL patterns detected."
        )

    return risk_level, score, reasons


# =========================================================
# QR CODE DECODER
# =========================================================

def decode_qr(file_bytes):

    try:

        # Convert uploaded bytes to NumPy array
        np_array = np.frombuffer(
            file_bytes,
            np.uint8
        )

        # Decode image in memory
        image = cv2.imdecode(
            np_array,
            cv2.IMREAD_COLOR
        )

        if image is None:

            return None

        detector = cv2.QRCodeDetector()

        # -------------------------------------------------
        # Attempt 1 - Normal image
        # -------------------------------------------------

        data, points, _ = detector.detectAndDecode(
            image
        )

        if data:

            return data.strip()

        # -------------------------------------------------
        # Attempt 2 - Resize
        # -------------------------------------------------

        height, width = image.shape[:2]

        if width < 1000:

            scale = 1000 / width

            new_size = (
                int(width * scale),
                int(height * scale)
            )

            resized = cv2.resize(
                image,
                new_size
            )

            data, points, _ = (
                detector.detectAndDecode(
                    resized
                )
            )

            if data:

                return data.strip()

        # -------------------------------------------------
        # Attempt 3 - Grayscale
        # -------------------------------------------------

        gray = cv2.cvtColor(
            image,
            cv2.COLOR_BGR2GRAY
        )

        data, points, _ = (
            detector.detectAndDecode(
                gray
            )
        )

        if data:

            return data.strip()

        # -------------------------------------------------
        # Attempt 4 - Threshold
        # -------------------------------------------------

        _, threshold = cv2.threshold(
            gray,
            0,
            255,
            cv2.THRESH_BINARY + cv2.THRESH_OTSU
        )

        data, points, _ = (
            detector.detectAndDecode(
                threshold
            )
        )

        if data:

            return data.strip()

    except Exception as error:

        print(
            "QR Decode Error:",
            error
        )

        return None

    return None


# =========================================================
# HOME / SCANNER
# =========================================================

@app.route("/")
def home():

    if "username" not in session:

        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html"
    )


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
        ).strip()

        if (
            username == "admin"
            and password == "qrgurad123"
        ):

            session["username"] = username

            return redirect(
                url_for("home")
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
# SCAN QR CODE
# =========================================================

@app.route(
    "/scan",
    methods=["POST"]
)
def scan():

    if "username" not in session:

        return redirect(
            url_for("login")
        )

    # -----------------------------------------------------
    # Get uploaded QR file
    # -----------------------------------------------------

    uploaded_file = request.files.get(
        "qr_file"
    )

    if uploaded_file is None:

        return render_template(
            "index.html",
            error="Please select a QR image."
        )

    if uploaded_file.filename == "":

        return render_template(
            "index.html",
            error="Please select a QR image."
        )

    # -----------------------------------------------------
    # Read file into memory
    # -----------------------------------------------------

    file_bytes = uploaded_file.read()

    if not file_bytes:

        return render_template(
            "index.html",
            error="Uploaded file is empty."
        )

    # -----------------------------------------------------
    # Decode QR
    # -----------------------------------------------------

    url = decode_qr(
        file_bytes
    )

    if not url:

        return render_template(
            "index.html",
            error="Could not detect a URL from this QR image."
        )

    # -----------------------------------------------------
    # Analyze URL
    # -----------------------------------------------------

    risk_level, score, reasons = analyze_url(
        url
    )

    # -----------------------------------------------------
    # Save reasons
    # -----------------------------------------------------

    reasons_text = " | ".join(
        reasons
    )

    # -----------------------------------------------------
    # Save scan to database
    # -----------------------------------------------------

    conn = sqlite3.connect(
        DB_PATH
    )

    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scans
        (url, risk_level, score, reasons)
        VALUES (?, ?, ?, ?)
    """, (
        url,
        risk_level,
        score,
        reasons_text
    ))

    scan_id = cursor.lastrowid

    conn.commit()

    conn.close()

    # =====================================================
    # IMPORTANT FIX
    # result.html expects "result"
    # =====================================================

    result = {
        "id": scan_id,
        "url": url,
        "risk": risk_level,
        "risk_level": risk_level,
        "score": score,
        "reasons": reasons
    }

    # -----------------------------------------------------
    # Display result
    # -----------------------------------------------------

    return render_template(
        "result.html",
        result=result,

        # Also keep individual variables
        # in case result.html uses them
        scan_id=scan_id,
        url=url,
        risk_level=risk_level,
        score=score,
        reasons=reasons
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if "username" not in session:

        return redirect(
            url_for("login")
        )

    conn = sqlite3.connect(
        DB_PATH
    )

    cursor = conn.cursor()

    # Total scans
    cursor.execute(
        "SELECT COUNT(*) FROM scans"
    )

    total_scans = cursor.fetchone()[0]

    # High risk
    cursor.execute(
        "SELECT COUNT(*) FROM scans "
        "WHERE risk_level = 'HIGH'"
    )

    high_risk = cursor.fetchone()[0]

    # Medium risk
    cursor.execute(
        "SELECT COUNT(*) FROM scans "
        "WHERE risk_level = 'MEDIUM'"
    )

    medium_risk = cursor.fetchone()[0]

    # Low risk
    cursor.execute(
        "SELECT COUNT(*) FROM scans "
        "WHERE risk_level = 'LOW'"
    )

    low_risk = cursor.fetchone()[0]

    conn.close()

    stats = {
        "total": total_scans,
        "high": high_risk,
        "medium": medium_risk,
        "low": low_risk
    }

    return render_template(
        "dashboard.html",
        stats=stats
    )


# =========================================================
# HISTORY
# =========================================================

@app.route("/history")
def history():

    if "username" not in session:

        return redirect(
            url_for("login")
        )

    conn = sqlite3.connect(
        DB_PATH
    )

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            url,
            risk_level,
            score,
            reasons
        FROM scans
        ORDER BY id DESC
    """)

    scans = cursor.fetchall()

    conn.close()

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

    if "username" not in session:

        return redirect(
            url_for("login")
        )

    conn = sqlite3.connect(
        DB_PATH
    )

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            url,
            risk_level,
            score,
            reasons
        FROM scans
        WHERE id = ?
    """, (
        scan_id,
    ))

    scan = cursor.fetchone()

    conn.close()

    if scan is None:

        return "Scan not found", 404

    # -----------------------------------------------------
    # ReportLab
    # -----------------------------------------------------

    from reportlab.pdfgen import canvas

    pdf_buffer = io.BytesIO()

    pdf = canvas.Canvas(
        pdf_buffer
    )

    pdf.setTitle(
        "QRGuard Scan Report"
    )

    pdf.drawString(
        50,
        800,
        "QRGuard - QR Code Phishing Detection Report"
    )

    pdf.drawString(
        50,
        770,
        f"Scan ID: {scan[0]}"
    )

    pdf.drawString(
        50,
        745,
        f"URL: {scan[1]}"
    )

    pdf.drawString(
        50,
        720,
        f"Risk Level: {scan[2]}"
    )

    pdf.drawString(
        50,
        695,
        f"Risk Score: {scan[3]}"
    )

    pdf.drawString(
        50,
        660,
        "Analysis:"
    )

    y = 635

    for reason in scan[4].split(" | "):

        pdf.drawString(
            70,
            y,
            "- " + reason[:100]
        )

        y -= 25

        if y < 60:

            pdf.showPage()

            y = 800

    pdf.save()

    pdf_buffer.seek(0)

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f"qrgurad_report_{scan_id}.pdf",
        mimetype="application/pdf"
    )


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/health")
def health():

    return "QRGuard is running"


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
