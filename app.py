from flask import Flask, render_template, request, redirect, url_for, session, send_file
from werkzeug.utils import secure_filename
from functools import wraps
from urllib.parse import urlparse, unquote
import cv2
import os
import uuid
import sqlite3
import ipaddress
import io
import html

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm


app = Flask(__name__)

app.secret_key = "QRGuard-Local-Project-Secret-Key-2026"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

DATABASE = os.path.join(BASE_DIR, "qrgurad.db")

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "bmp"}

LOGIN_USERNAME = "admin"
LOGIN_PASSWORD = "qrgurad123"


# =========================================================
# DATABASE
# =========================================================

def get_db():
    conn = sqlite3.connect(DATABASE)
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

    # Check existing database columns
    columns = conn.execute("PRAGMA table_info(scans)").fetchall()

    column_names = [column["name"] for column in columns]

    # Add created_at if old database does not have it
    if "created_at" not in column_names:
        conn.execute("""
            ALTER TABLE scans
            ADD COLUMN created_at TIMESTAMP
        """)

        conn.execute("""
            UPDATE scans
            SET created_at = CURRENT_TIMESTAMP
            WHERE created_at IS NULL
        """)

    # Add reasons if old database does not have it
    if "reasons" not in column_names:
        conn.execute("""
            ALTER TABLE scans
            ADD COLUMN reasons TEXT
        """)

    conn.commit()
    conn.close()


# =========================================================
# LOGIN
# =========================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("logged_in"):
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username == LOGIN_USERNAME and password == LOGIN_PASSWORD:

            session["logged_in"] = True

            return redirect(url_for("index"))

        return render_template(
            "login.html",
            error="Invalid username or password."
        )

    return render_template("login.html")


@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# =========================================================
# FILE VALIDATION
# =========================================================

def allowed_file(filename):

    if not filename:
        return False

    if "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()

    return extension in ALLOWED_EXTENSIONS


# =========================================================
# URL VALIDATION
# =========================================================

def validate_url(url):

    if not url:
        return False, "No URL was detected in the QR code."

    url = url.strip()

    if len(url) > 2048:
        return False, "The detected URL is too long."

    try:

        parsed = urlparse(url)

        if parsed.scheme.lower() not in {"http", "https"}:
            return False, "The QR code does not contain a valid HTTP/HTTPS URL."

        if not parsed.hostname:
            return False, "The detected URL does not contain a valid hostname."

        try:
            parsed.port
        except ValueError:
            return False, "The URL contains an invalid port number."

        return True, ""

    except Exception:

        return False, "The detected URL could not be validated."


# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_url(url):

    score = 0
    reasons = []
    details = []

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # 1. Long URL
    if len(url) > 100:

        score += 15

        reasons.append(
            "The URL is unusually long."
        )

        details.append(
            ("Long URL", 15)
        )

    # 2. HTTPS
    if parsed.scheme.lower() != "https":

        score += 15

        reasons.append(
            "The URL does not use HTTPS."
        )

        details.append(
            ("No HTTPS", 15)
        )

    # 3. IP address
    try:

        ipaddress.ip_address(hostname)

        score += 25

        reasons.append(
            "The hostname is an IP address instead of a normal domain."
        )

        details.append(
            ("IP address hostname", 25)
        )

    except ValueError:
        pass

    # 4. Embedded username/password
    if parsed.username or parsed.password:

        score += 20

        reasons.append(
            "The URL contains embedded username or password information."
        )

        details.append(
            ("Embedded credentials", 20)
        )

    # 5. @ symbol
    if "@" in url:

        score += 10

        reasons.append(
            "The URL contains an @ symbol."
        )

        details.append(
            ("At symbol", 10)
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

    found_keywords = [
        word
        for word in suspicious_keywords
        if word in url.lower()
    ]

    if found_keywords:

        score += 10

        reasons.append(
            "The URL contains security-sensitive keywords: "
            + ", ".join(found_keywords[:5])
        )

        details.append(
            ("Suspicious keywords", 10)
        )

    # 7. Multiple subdomains
    if hostname.count(".") >= 3:

        score += 10

        reasons.append(
            "The hostname contains multiple subdomains."
        )

        details.append(
            ("Multiple subdomains", 10)
        )

    # 8. Hyphen
    if "-" in hostname:

        score += 5

        reasons.append(
            "The hostname contains hyphens."
        )

        details.append(
            ("Hyphenated hostname", 5)
        )

    # 9. Multiple digits
    digit_count = sum(
        character.isdigit()
        for character in hostname
    )

    if digit_count >= 3:

        score += 5

        reasons.append(
            "The hostname contains several numeric characters."
        )

        details.append(
            ("Multiple digits", 5)
        )

    # 10. Long hostname
    if len(hostname) > 30:

        score += 10

        reasons.append(
            "The hostname is unusually long."
        )

        details.append(
            ("Long hostname", 10)
        )

    # 11. Special characters
    if "%" in url or "_" in url:

        score += 5

        reasons.append(
            "The URL contains encoded or unusual special characters."
        )

        details.append(
            ("Special characters", 5)
        )

    # 12. Encoded URL
    try:

        decoded_url = unquote(url)

        if decoded_url != url:

            score += 10

            reasons.append(
                "The URL contains percent-encoded content."
            )

            details.append(
                ("Encoded URL content", 10)
            )

    except Exception:
        pass

    # 13. Long path
    if len(path) > 60:

        score += 10

        reasons.append(
            "The URL path is unusually long."
        )

        details.append(
            ("Long path", 10)
        )

    # 14. Many query parameters
    if query:

        parameter_count = len(query.split("&"))

        if parameter_count >= 4:

            score += 10

            reasons.append(
                "The URL contains many query parameters."
            )

            details.append(
                ("Many query parameters", 10)
            )

    # 15. Potentially dangerous file extension
    suspicious_extensions = (
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".apk"
    )

    if path.lower().endswith(suspicious_extensions):

        score += 15

        reasons.append(
            "The URL path ends with a potentially dangerous file type."
        )

        details.append(
            ("Potentially dangerous file extension", 15)
        )

    # 16. Punycode
    if "xn--" in hostname.lower():

        score += 15

        reasons.append(
            "The hostname uses Punycode."
        )

        details.append(
            ("Punycode hostname", 15)
        )

    # 17. Multiple hyphens
    if hostname.count("-") >= 3:

        score += 10

        reasons.append(
            "The hostname contains several hyphens."
        )

        details.append(
            ("Multiple hyphens", 10)
        )

    # 18. Non-standard port
    try:

        port = parsed.port

        if port is not None and port not in {80, 443}:

            score += 10

            reasons.append(
                "The URL uses a non-standard HTTP/HTTPS port."
            )

            details.append(
                ("Non-standard port", 10)
            )

    except ValueError:
        pass

    # 19. Long hostname label
    labels = hostname.split(".")

    if any(len(label) > 25 for label in labels):

        score += 5

        reasons.append(
            "A hostname label is unusually long."
        )

        details.append(
            ("Long hostname label", 5)
        )

    # Maximum score
    score = min(score, 100)

    # Risk level
    if score <= 30:

        risk = "LOW RISK"

    elif score <= 60:

        risk = "MEDIUM RISK"

    else:

        risk = "HIGH RISK"

    if not reasons:

        reasons.append(
            "No major suspicious URL characteristics were detected "
            "by the current rule set."
        )

    return {
        "url": url,
        "score": score,
        "risk": risk,
        "reasons": reasons,
        "details": details
    }


# =========================================================
# SAVE SCAN
# =========================================================

def save_scan(result):

    conn = get_db()

    reasons_text = " | ".join(
        result["reasons"]
    )

    cursor = conn.execute("""
        INSERT INTO scans
        (url, score, risk, reasons, created_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (
        result["url"],
        result["score"],
        result["risk"],
        reasons_text
    ))

    scan_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return scan_id


# =========================================================
# MAIN SCANNER
# =========================================================

@app.route("/", methods=["GET", "POST"])
@login_required
def index():

    error = None

    if request.method == "POST":

        if "qr_image" not in request.files:

            error = "Please select a QR image."

            return render_template(
                "index.html",
                error=error
            )

        uploaded_file = request.files["qr_image"]

        if uploaded_file.filename == "":

            error = "Please select a QR image."

            return render_template(
                "index.html",
                error=error
            )

        if not allowed_file(uploaded_file.filename):

            error = (
                "Unsupported file type. "
                "Use PNG, JPG, JPEG, WEBP or BMP."
            )

            return render_template(
                "index.html",
                error=error
            )

        original_filename = secure_filename(
            uploaded_file.filename
        )

        unique_filename = (
            str(uuid.uuid4())
            + "_"
            + original_filename
        )

        file_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            unique_filename
        )

        try:

            uploaded_file.save(file_path)

            image = cv2.imread(file_path)

            if image is None:

                error = (
                    "The uploaded file could not be read as an image."
                )

                return render_template(
                    "index.html",
                    error=error
                )

            detector = cv2.QRCodeDetector()

            data, points, _ = detector.detectAndDecode(image)

            if not data:

                error = (
                    "No readable QR code was detected in this image. "
                    "Please try a clearer QR image."
                )

                return render_template(
                    "index.html",
                    error=error
                )

            is_valid, validation_error = validate_url(data)

            if not is_valid:

                error = validation_error

                return render_template(
                    "index.html",
                    error=error
                )

            result = analyze_url(data)

            scan_id = save_scan(result)

            result["id"] = scan_id

            return render_template(
                "result.html",
                result=result
            )

        except cv2.error:

            error = (
                "The image could not be processed. "
                "Please try another QR image."
            )

        except sqlite3.Error:

            error = (
                "The scan was analyzed, but the database "
                "could not save the result."
            )

        except Exception as exception:

            print(
                "QRGuard Error:",
                exception
            )

            error = (
                "Something went wrong while processing the QR image."
            )

        finally:

            if os.path.exists(file_path):

                try:
                    os.remove(file_path)
                except Exception:
                    pass

        return render_template(
            "index.html",
            error=error
        )

    return render_template(
        "index.html",
        error=error
    )


# =========================================================
# FILE TOO LARGE
# =========================================================

@app.errorhandler(413)
def request_entity_too_large(error):

    if session.get("logged_in"):

        return render_template(
            "index.html",
            error="File is too large. Maximum allowed size is 5 MB."
        ), 413

    return redirect(
        url_for("login")
    )


# =========================================================
# 404
# =========================================================

@app.errorhandler(404)
def page_not_found(error):

    if session.get("logged_in"):

        return render_template(
            "index.html",
            error="The requested page was not found."
        ), 404

    return redirect(
        url_for("login")
    )


# =========================================================
# 500
# =========================================================

@app.errorhandler(500)
def internal_server_error(error):

    if session.get("logged_in"):

        return render_template(
            "index.html",
            error="An internal application error occurred."
        ), 500

    return redirect(
        url_for("login")
    )


# =========================================================
# HISTORY
# =========================================================

@app.route("/history")
@login_required
def history():

    conn = get_db()

    scans = conn.execute("""
        SELECT *
        FROM scans
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "history.html",
        scans=scans
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    conn = get_db()

    total = conn.execute(
        "SELECT COUNT(*) FROM scans"
    ).fetchone()[0]

    low = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE score <= 30"
    ).fetchone()[0]

    medium = conn.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE score > 30 AND score <= 60
        """
    ).fetchone()[0]

    high = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE score > 60"
    ).fetchone()[0]

    recent_scans = conn.execute("""
        SELECT *
        FROM scans
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()

    conn.close()

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


# =========================================================
# PDF REPORT
# =========================================================

@app.route("/report/<int:scan_id>")
@login_required
def report(scan_id):

    conn = get_db()

    scan = conn.execute("""
        SELECT *
        FROM scans
        WHERE id = ?
    """, (scan_id,)).fetchone()

    conn.close()

    if scan is None:

        return "Scan report not found.", 404

    result = analyze_url(
        scan["url"]
    )

    result["id"] = scan["id"]
    result["score"] = scan["score"]
    result["risk"] = scan["risk"]

    # Safely read scan time
    scan_time = scan["created_at"]

    if not scan_time:
        scan_time = "Time not available"

    buffer = io.BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "QRGuardTitle",
        parent=styles["Title"],
        fontSize=22,
        leading=26,
        spaceAfter=12
    )

    heading_style = ParagraphStyle(
        "QRGuardHeading",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        spaceBefore=10,
        spaceAfter=8
    )

    normal_style = ParagraphStyle(
        "QRGuardNormal",
        parent=styles["BodyText"],
        fontSize=9.5,
        leading=14
    )

    story = []

    story.append(
        Paragraph(
            "QRGuard - QR Code Phishing Detection Report",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Defensive URL analysis report generated by QRGuard.",
            normal_style
        )
    )

    story.append(
        Spacer(1, 10)
    )

    safe_url = html.escape(
        str(scan["url"])
    )

    safe_risk = html.escape(
        str(scan["risk"])
    )

    summary_data = [
        ["Scan ID", str(scan["id"])],
        [
            "Detected URL",
            Paragraph(
                safe_url,
                normal_style
            )
        ],
        [
            "Risk Score",
            str(scan["score"]) + " / 100"
        ],
        [
            "Risk Level",
            safe_risk
        ],
        [
            "Scanned Time",
            html.escape(str(scan_time))
        ]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[
            40 * mm,
            130 * mm
        ]
    )

    summary_table.setStyle(
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
                colors.lightgrey
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                9
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
        summary_table
    )

    # -----------------------------------------------------
    # Detection Reasons
    # -----------------------------------------------------

    story.append(
        Paragraph(
            "Detection Reasons",
            heading_style
        )
    )

    for reason in result["reasons"]:

        story.append(
            Paragraph(
                "• " + html.escape(reason),
                normal_style
            )
        )

    # -----------------------------------------------------
    # Score Breakdown
    # -----------------------------------------------------

    story.append(
        Paragraph(
            "Score Breakdown",
            heading_style
        )
    )

    breakdown_data = [
        ["Detection Rule", "Points"]
    ]

    for name, points in result["details"]:

        breakdown_data.append([
            name,
            str(points)
        ])

    if len(breakdown_data) == 1:

        breakdown_data.append([
            "No triggered rules",
            "0"
        ])

    breakdown_table = Table(
        breakdown_data,
        colWidths=[
            140 * mm,
            30 * mm
        ]
    )

    breakdown_table.setStyle(
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
                (-1, 0),
                colors.lightgrey
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                9
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
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
        breakdown_table
    )

    # -----------------------------------------------------
    # Methodology
    # -----------------------------------------------------

    story.append(
        Paragraph(
            "Methodology",
            heading_style
        )
    )

    methodology = (
        "QRGuard performs static URL analysis using predefined "
        "heuristic rules. The submitted URL is analyzed as text. "
        "QRGuard does not automatically open or visit the detected URL."
    )

    story.append(
        Paragraph(
            methodology,
            normal_style
        )
    )

    # -----------------------------------------------------
    # Disclaimer
    # -----------------------------------------------------

    story.append(
        Paragraph(
            "Disclaimer",
            heading_style
        )
    )

    disclaimer = (
        "This report is intended for educational and defensive "
        "cybersecurity analysis. A risk score is an indicator produced "
        "by the configured rules and is not a guarantee that a URL is "
        "malicious or safe."
    )

    story.append(
        Paragraph(
            disclaimer,
            normal_style
        )
    )

    document.build(story)

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"QRGuard_Report_{scan_id}.pdf",
        mimetype="application/pdf"
    )


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":

    init_db()

    print("")
    print("======================================")
    print("        QRGuard Security System")
    print("======================================")
    print("Server: http://127.0.0.1:5000")
    print("Username: admin")
    print("Password: qrgurad123")
    print("======================================")
    print("")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )