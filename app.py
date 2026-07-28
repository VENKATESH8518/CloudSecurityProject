import os
import csv
import io
from flask import make_response



print("******** APP.PY LOADED ********")
from werkzeug.utils import secure_filename
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session
)

from flask_bcrypt import Bcrypt
from database import (fetch_one, fetch_all, execute_query,execute_insert)
from utils.otp import generate_otp
from flask_mail import Mail
from config import Config
from utils.email_sender import send_otp
from utils.aes import encrypt_file, decrypt_file
from utils.hashing import (generate_sha256,verify_file_integrity)
from utils.aes import encrypt_file, decrypt_file
from flask import send_file
from utils.hash import generate_sha256
from werkzeug.utils import secure_filename
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph
from reportlab.lib.units import inch
from io import BytesIO


app = Flask(__name__)
app.config.from_object(Config)

mail = Mail(app)
app.secret_key = "cloud_security_secret_key"

bcrypt = Bcrypt(app)

UPLOAD_FOLDER = "cloud_storage/uploads"

ENCRYPTED_FOLDER = "cloud_storage/encrypted"

DOWNLOAD_FOLDER = "cloud_storage/downloads"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

app.config["ENCRYPTED_FOLDER"] = ENCRYPTED_FOLDER

app.config["DOWNLOAD_FOLDER"] = DOWNLOAD_FOLDER

os.makedirs(
    ENCRYPTED_FOLDER,
    exist_ok=True
)

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

os.makedirs(
    DOWNLOAD_FOLDER,
    exist_ok=True
)

ALLOWED_EXTENSIONS = {
    "txt",
    "pdf",
    "doc",
    "docx",
    "png",
    "jpg",
    "jpeg"
}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Create upload folder automatically
os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

# Check allowed file types
def allowed_file(filename):

    return (
        "." in filename
        and
        filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )

# ==========================
# HOME PAGE
# ==========================

@app.route("/")
def home():
    return render_template("index.html")


# ==========================
# ABOUT PAGE
# ==========================

@app.route("/about")
def about():
    return render_template("about.html")


# ==========================
# SERVICES PAGE
# ==========================

@app.route("/services")
def services():
    return render_template("services.html")


# ==========================
# CONTACT PAGE
# ==========================

@app.route("/contact")
def contact():
    return render_template("contact.html")


# ==========================
# LOGIN PAGE
# ==========================



@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        # ==========================
        # CHECK ADMIN LOGIN
        # ==========================

        admin = fetch_one(
            "SELECT * FROM admins WHERE username=?",
            (username,)
        )

        if admin:

            if admin["password"] == password:

                session["username"] = admin["username"]
                session["fullname"] = "Administrator"
                session["role"] = "Admin"

                execute_query(
                    """
                    INSERT INTO security_logs
                    (
                        username,
                        activity,
                        ip_address
                    )
                    VALUES
                    (
                        ?, ?, ?
                    )
                    """,
                    (
                        username,
                        "Admin Login",
                        request.remote_addr
                    )
                )

                flash("Admin Login Successful!", "success")

                return redirect(url_for("admin_dashboard"))

        # ==========================
        # CHECK USER LOGIN
        # ==========================

        user = fetch_one(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )

        if user:

            if bcrypt.check_password_hash(user["password"], password):

                session["username"] = user["username"]
                session["fullname"] = user["fullname"]
                session["role"] = "User"

                execute_query(
                    """
                    INSERT INTO security_logs
                    (
                        username,
                        activity,
                        ip_address
                    )
                    VALUES
                    (
                        ?, ?, ?
                    )
                    """,
                    (
                        username,
                        "User Login",
                        request.remote_addr
                    )
                )

                flash("User Login Successful!", "success")

                return redirect(url_for("dashboard"))

        # ==========================
        # MODULE 6.2
        # FAILED LOGIN DETECTION
        # ==========================

        execute_query(
            """
            INSERT INTO security_logs
            (
                username,
                activity,
                ip_address
            )
            VALUES
            (
                ?, ?, ?
            )
            """,
            (
                username,
                "Failed Login Attempt",
                request.remote_addr
            )
        )

        flash("Invalid Username or Password", "danger")

    return render_template("login.html")


# ==========================
# REGISTER PAGE
# ==========================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        fullname = request.form.get("fullname")
        email = request.form.get("email")
        phone = request.form.get("phone")
        username = request.form.get("username")
        password = request.form.get("password")

        confirm_password = request.form.get("confirm_password")

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        # Check if username already exists
        user = fetch_one(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )

        if user:
            flash("Username already exists.", "danger")
            return redirect(url_for("register"))

        # Check if email already exists
        user = fetch_one(
            "SELECT * FROM users WHERE email=?",
            (email,)
        )

        if user:
            flash("Email already registered.", "danger")
            return redirect(url_for("register"))

        
        # Hash password
        hashed_password = bcrypt.generate_password_hash(
             password
        ).decode("utf-8")

        # Generate OTP
        otp = generate_otp()

        print("=" * 50)
        print("Generated OTP:", otp)
        print("=" * 50)

               # Save user
        execute_query(
            """
            INSERT INTO users
            (
                fullname,
                email,
                phone,
                username,
                password
            )
            VALUES
            (
                ?, ?, ?, ?, ?
            )
            """,
            (
                fullname,
                email,
                phone,
                username,
                hashed_password
            )
        )

        # Save OTP into database
        execute_query(
            """
            INSERT INTO otp
            (
                email,
                otp,
                expiry_time
            )
            VALUES
            (
                ?, ?, datetime('now','+5 minutes')
            )
            """,
            (
                email,
                otp
            )
        )


        # Send OTP Email
        send_otp(
            mail,
            email,
            otp
        )    

        # Store email in session
        session["verification_email"] = email

        flash("Registration Successful! Please verify your OTP.", "success")

        return redirect(url_for("verify_otp"))

    return render_template("register.html")

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():

    if "verification_email" not in session:

        flash("Please register first.", "warning")

        return redirect(url_for("register"))

    email = session["verification_email"]

    if request.method == "POST":

        entered_otp = request.form.get("otp")

        otp_record = fetch_one(
            """
            SELECT * FROM otp
            WHERE email=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (email,)
        )

        if otp_record is None:

            flash("OTP not found.", "danger")

            return redirect(url_for("verify_otp"))

        if entered_otp == otp_record["otp"]:

            execute_query(
                """
                UPDATE users
                SET verified=1
                WHERE email=?
                """,
                (email,)
            )

            execute_query(
                """
                DELETE FROM otp
                WHERE email=?
                """,
                (email,)
            )

            session.pop("verification_email", None)

            flash(
                "OTP Verified Successfully! Please Login.",
                "success"
            )

            return redirect(url_for("login"))

        flash("Invalid OTP.", "danger")

    return render_template("verify_otp.html")

@app.route("/dashboard")
def dashboard():

    if "username" not in session:

        flash("Please login first.", "warning")

        return redirect(url_for("login"))

    if session.get("role") != "User":

        return redirect(url_for("admin_dashboard"))

    return render_template(
        "dashboard.html",
        username=session["username"],
        fullname=session["fullname"]
    )

@app.route("/logout")
def logout():

    session.clear()

    flash("Logged out successfully.", "success")

    return redirect(url_for("login"))


@app.route("/users")
def users():

    if "username" not in session:

        flash("Please login first.", "warning")

        return redirect(url_for("login"))

    if session.get("role") != "Admin":

        flash("Access Denied.", "danger")

        return redirect(url_for("dashboard"))

    users = fetch_all(
        "SELECT * FROM users ORDER BY id DESC"
    )

    return render_template(
        "users.html",
        users=users
    )


@app.route("/admin-dashboard")
def admin_dashboard():

    # Check whether user is logged in
    if "username" not in session:
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    # Allow only Admin users
    if session.get("role") != "Admin":
        flash("Access Denied.", "danger")
        return redirect(url_for("dashboard"))

    # Dashboard Statistics
    total_users = fetch_one(
        "SELECT COUNT(*) AS total FROM users"
    )["total"]

    total_files = fetch_one(
        "SELECT COUNT(*) AS total FROM files"
    )["total"]

    total_logs = fetch_one(
        "SELECT COUNT(*) AS total FROM security_logs"
    )["total"]

    total_downloads = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM security_logs
        WHERE activity LIKE '%Downloaded%'
        """
    )["total"]

    # Recent Downloads
    recent_downloads = fetch_all(
        """
        SELECT
            username,
            activity,
            log_time
        FROM security_logs
        WHERE activity LIKE '%Downloaded%'
        ORDER BY log_time DESC
        LIMIT 5
        """
    )

    # Open Admin Dashboard
    return render_template(
        "admin_dashboard.html",
        username=session["username"],
        total_users=total_users,
        total_files=total_files,
        total_logs=total_logs,
        total_downloads=total_downloads,
        recent_downloads=recent_downloads
    )

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form.get("email")

        user = fetch_one(
            "SELECT * FROM users WHERE email=?",
            (email,)
        )

        if user is None:

            flash("Email not found.", "danger")

            return redirect(url_for("forgot_password"))

        otp = generate_otp()

        execute_query(
            """
            INSERT INTO otp
            (
                email,
                otp,
                expiry_time
            )
            VALUES
            (
                ?, ?, datetime('now','+5 minutes')
            )
            """,
            (
                email,
                otp
            )
        )

        send_otp(
            mail,
            email,
            otp
        )

        session["reset_email"] = email

        flash(
            "OTP has been sent to your email.",
            "success"
        )

        return redirect(url_for("reset_password"))

    return render_template("forgot_password.html")

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():

    if "reset_email" not in session:

        return redirect(url_for("forgot_password"))

    email = session["reset_email"]

    if request.method == "POST":

        otp = request.form.get("otp")

        password = request.form.get("password")

        confirm = request.form.get("confirm_password")

        if password != confirm:

            flash("Passwords do not match.", "danger")

            return redirect(url_for("reset_password"))

        otp_record = fetch_one(
            """
            SELECT * FROM otp
            WHERE email=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (email,)
        )

        if otp_record is None:

            flash("OTP not found.", "danger")

            return redirect(url_for("reset_password"))

        if otp != otp_record["otp"]:

            flash("Invalid OTP.", "danger")

            return redirect(url_for("reset_password"))

        hashed = bcrypt.generate_password_hash(
            password
        ).decode("utf-8")

        execute_query(
            """
            UPDATE users
            SET password=?
            WHERE email=?
            """,
            (
                hashed,
                email
            )
        )

        execute_query(
            "DELETE FROM otp WHERE email=?",
            (email,)
        )

        session.pop("reset_email", None)

        flash(
            "Password updated successfully.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template("reset_password.html")


@app.route("/security-report")
def security_report():

    if "username" not in session:
        return redirect(url_for("login"))

    # --------------------------------------------------
    # Dashboard Statistics
    # --------------------------------------------------

    users = fetch_one(
        "SELECT COUNT(*) AS total FROM users"
    )
    total_users = users["total"] if users else 0

    files = fetch_one(
        "SELECT COUNT(*) AS total FROM files"
    )
    total_files = files["total"] if files else 0

    logs = fetch_one(
        "SELECT COUNT(*) AS total FROM security_logs"
    )
    total_logs = logs["total"] if logs else 0

    # --------------------------------------------------
    # User Statistics
    # --------------------------------------------------

    active = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM users
        WHERE status='Active'
        """
    )
    active_users = active["total"] if active else 0

    admin = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM users
        WHERE role='Admin'
        """
    )
    admins = admin["total"] if admin else 0

    normal = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM users
        WHERE role='User'
        """
    )
    normal_users = normal["total"] if normal else 0

    # --------------------------------------------------
    # File Statistics
    # --------------------------------------------------

    secure = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM files
        WHERE verification_status='Secure'
        """
    )
    secure_files = secure["total"] if secure else 0

    tampered = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM files
        WHERE verification_status='Tampered'
        """
    )
    tampered_files = tampered["total"] if tampered else 0

    # --------------------------------------------------
    # Module 5.4
    # Recent Security Activities
    # --------------------------------------------------

    recent_logs = fetch_all(
        """
        SELECT
            username,
            activity,
            ip_address,
            log_time
        FROM security_logs
        ORDER BY log_time DESC
        LIMIT 10
        """
    )

    # --------------------------------------------------
    # Module 5.5
    # Recent Uploaded Files
    # --------------------------------------------------

    recent_files = fetch_all(
        """
        SELECT
            id,
            username,
            original_filename,
            upload_time,
            verification_status
        FROM files
        ORDER BY upload_time DESC
        LIMIT 10
        """
    )

    # --------------------------------------------------
    # Module 5.6
    # Verification Status Summary
    # --------------------------------------------------

    not_verified = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM files
        WHERE verification_status IS NULL
           OR verification_status=''
           OR verification_status='Not Verified'
        """
    )

    not_verified_files = (
        not_verified["total"]
        if not_verified
        else 0
    )

    # --------------------------------------------------
    # Module 5.7
    # System Health Status
    # --------------------------------------------------

    system_health = "Healthy"

    encryption_status = "Enabled"

    database_status = "Connected"

    session_status = "Active"

    firewall_status = "Protected"

    # --------------------------------------------------
    # Module 5.8
    # Cloud Storage Statistics
    # --------------------------------------------------

    total_storage = 0

    uploaded_files = fetch_all(
        """
        SELECT encrypted_filename
        FROM files
        """
    )

    for file in uploaded_files:

        file_path = os.path.join(
            app.config["ENCRYPTED_FOLDER"],
            file["encrypted_filename"]
        )

        if os.path.exists(file_path):

            total_storage += os.path.getsize(file_path)

    storage_mb = round(
        total_storage / (1024 * 1024),
        2
    )

    # --------------------------------------------------
    # Render Template
    # --------------------------------------------------

    return render_template(
        "security_report.html",
        total_users=total_users,
        total_files=total_files,
        total_logs=total_logs,
        active_users=active_users,
        admins=admins,
        normal_users=normal_users,
        secure_files=secure_files,
        tampered_files=tampered_files,
        recent_logs=recent_logs,
        recent_files=recent_files,
        not_verified_files=not_verified_files,
        system_health=system_health,
        encryption_status=encryption_status,
        database_status=database_status,
        session_status=session_status,
        firewall_status=firewall_status,
        storage_mb=storage_mb
    )

@app.route("/intrusion-detection")
def intrusion_detection():

    if "username" not in session:

        return redirect(url_for("login"))

    total = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM security_logs
        WHERE activity LIKE '%Failed%'
        """
    )

    total_intrusions = total["total"] if total else 0

    today = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM security_logs
        WHERE activity LIKE '%Failed%'
        AND DATE(log_time)=DATE('now')
        """
    )

    today_intrusions = today["total"] if today else 0

    return render_template(
        "intrusion_detection.html",
        total_intrusions=total_intrusions,
        today_intrusions=today_intrusions
    )

@app.route("/intrusion-logs")
def intrusion_logs():

    if "username" not in session:
        return redirect(url_for("login"))

    search = request.args.get("search", "")
    selected_date = request.args.get("date", "")

    query = """
        SELECT
            id,
            username,
            activity,
            ip_address,
            log_time
        FROM security_logs
        WHERE activity='Failed Login Attempt'
    """

    parameters = []

    if search:

        query += """
            AND
            (
                username LIKE ?
                OR ip_address LIKE ?
                OR activity LIKE ?
            )
        """

        parameters.extend([
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        ])

    if selected_date:

        query += " AND DATE(log_time)=?"

        parameters.append(selected_date)

    query += " ORDER BY log_time DESC"

    logs = fetch_all(query, tuple(parameters))

    total_intrusions = fetch_one("""
        SELECT COUNT(*) AS total
        FROM security_logs
        WHERE activity='Failed Login Attempt'
    """)

    total_intrusions = total_intrusions["total"] if total_intrusions else 0

    today_intrusions = fetch_one("""
        SELECT COUNT(*) AS total
        FROM security_logs
        WHERE activity='Failed Login Attempt'
        AND DATE(log_time)=DATE('now')
    """)

    today_intrusions = today_intrusions["total"] if today_intrusions else 0

    unique_ips = fetch_one("""
        SELECT COUNT(DISTINCT ip_address) AS total
        FROM security_logs
        WHERE activity='Failed Login Attempt'
    """)

    unique_ips = unique_ips["total"] if unique_ips else 0

    unique_users = fetch_one("""
        SELECT COUNT(DISTINCT username) AS total
        FROM security_logs
        WHERE activity='Failed Login Attempt'
    """)

    unique_users = unique_users["total"] if unique_users else 0

    security_status = "Secure"

    if today_intrusions >= 5:
        security_status = "High Risk"

    elif today_intrusions >= 1:
        security_status = "Warning"

    return render_template(
        "intrusion_logs.html",
        logs=logs,
        search=search,
        selected_date=selected_date,
        total_intrusions=total_intrusions,
        today_intrusions=today_intrusions,
        unique_ips=unique_ips,
        unique_users=unique_users,
        security_status=security_status
    )


@app.route("/export-intrusion-logs")
def export_intrusion_logs():

    if "username" not in session:
        return redirect(url_for("login"))

    logs = fetch_all(
        """
        SELECT
            username,
            activity,
            ip_address,
            log_time
        FROM security_logs
        WHERE activity='Failed Login Attempt'
        ORDER BY log_time DESC
        """
    )

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "Username",
        "Activity",
        "IP Address",
        "Date & Time"
    ])

    for log in logs:

        writer.writerow([
            log["username"],
            log["activity"],
            log["ip_address"],
            log["log_time"]
        ])

    response = make_response(output.getvalue())

    response.headers["Content-Disposition"] = \
        "attachment; filename=Intrusion_Logs_Report.csv"

    response.headers["Content-type"] = "text/csv"

    return response

@app.route("/clear-intrusion-logs")
def clear_intrusion_logs():

    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "Admin":
        flash("Access Denied.", "danger")
        return redirect(url_for("dashboard"))

    execute_query(
        """
        DELETE FROM security_logs
        WHERE activity='Failed Login Attempt'
        """
    )

    execute_query(
        """
        INSERT INTO security_logs
        (
            username,
            activity,
            ip_address
        )
        VALUES
        (
            ?, ?, ?
        )
        """,
        (
            session["username"],
            "Cleared Intrusion Logs",
            request.remote_addr
        )
    )

    flash(
        "Intrusion Logs Cleared Successfully!",
        "success"
    )

    return redirect(url_for("intrusion_logs"))

@app.route("/blocked-ips")
def blocked_ips():

    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "Admin":
        flash("Access Denied.", "danger")
        return redirect(url_for("dashboard"))

    blocked_ips = fetch_all(
        """
        SELECT
            ip_address,
            COUNT(*) AS attempts,
            MAX(log_time) AS last_attempt
        FROM security_logs
        WHERE activity='Failed Login Attempt'
        GROUP BY ip_address
        HAVING COUNT(*) >= 3
        ORDER BY attempts DESC
        """
    )

    return render_template(
        "blocked_ips.html",
        blocked_ips=blocked_ips
    )


@app.route("/security-logs")
def security_logs():

    if "username" not in session:
        return redirect(url_for("login"))

    logs = fetch_all(
        """
        SELECT *
        FROM security_logs
        ORDER BY id DESC
        """
    )

    total_logs = len(logs)

    return render_template(
        "security_logs.html",
        logs=logs,
        total_logs=total_logs
    )

@app.route("/download-history")
def download_history():

    if "username" not in session:
        return redirect(url_for("login"))

    logs = fetch_all("""
        SELECT *
        FROM download_logs
        ORDER BY download_time DESC
    """) or []

    result = fetch_one("""
        SELECT COUNT(*) AS total
        FROM download_logs
    """)

    total_downloads = result["total"] if result else 0

    result = fetch_one("""
        SELECT COUNT(*) AS total
        FROM download_logs
        WHERE DATE(download_time)=DATE('now')
    """)

    today_downloads = result["total"] if result else 0

    result = fetch_one("""
        SELECT COUNT(DISTINCT username) AS total
        FROM download_logs
    """)

    unique_users = result["total"] if result else 0

    result = fetch_one("""
        SELECT
            file_name,
            COUNT(*) AS total
        FROM download_logs
        GROUP BY file_name
        ORDER BY total DESC
        LIMIT 1
    """)

    if result:
        top_file = result["file_name"]
        top_count = result["total"]
    else:
        top_file = "No Downloads"
        top_count = 0

    return render_template(
        "download_history.html",
        logs=logs,
        total_downloads=total_downloads,
        today_downloads=today_downloads,
        unique_users=unique_users,
        top_file=top_file,
        top_count=top_count
    )


@app.route("/export-download-history")
def export_download_history():

    if "username" not in session:
        return redirect(url_for("login"))

    logs = fetch_all(
        """
        SELECT
            id,
            username,
            file_name,
            ip_address,
            download_time
        FROM download_logs
        ORDER BY download_time DESC
        """
    )

    import io
    import csv

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Username",
        "Downloaded File",
        "IP Address",
        "Download Time"
    ])

    for log in logs:

        writer.writerow([
            log["id"],
            log["username"],
            log["file_name"],
            log["ip_address"],
            log["download_time"]
        ])

    response = make_response(output.getvalue())

    response.headers["Content-Disposition"] = \
        "attachment; filename=Download_History_Report.csv"

    response.headers["Content-Type"] = "text/csv"

    return response


@app.route("/download-security")
def download_security():

    if "username" not in session:
        return redirect(url_for("login"))

    logs = fetch_all(
        """
        SELECT *
        FROM download_logs
        ORDER BY download_time DESC
        """
    )

    total_downloads = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM download_logs
        """
    )

    if total_downloads:
        total = total_downloads["total"]
    else:
        total = 0

    return render_template(
        "download_security.html",
        logs=logs,
        total=total
    )





@app.route("/upload", methods=["GET", "POST"])
def upload():
    print("===================================")
    print("UPLOAD FUNCTION CALLED")
    print("REQUEST METHOD:", request.method)
    print("===================================")



    # Check if user is logged in
    if "username" not in session:

        flash("Please login first.", "warning")

        return redirect(url_for("login"))

    if request.method == "POST":
        print("UPLOAD ROUTE EXECUTED")

        # Check whether a file was submitted
        if "file" not in request.files:

            flash("No file selected.", "danger")

            return redirect(request.url)

        file = request.files["file"]

        # Check if filename is empty
        if file.filename == "":

            flash("Please choose a file.", "danger")

            return redirect(request.url)

        # Validate file extension
        if file and allowed_file(file.filename):

            # Secure filename
            filename = secure_filename(file.filename)

            # Save original file
            save_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                filename
            )

            file.save(save_path)

            # Encrypted file path
            encrypted_path = os.path.join(
                app.config["ENCRYPTED_FOLDER"],
                filename + ".enc"
            )

            print("Encrypting file...")
            # Encrypt the file
            key = encrypt_file(
                save_path,
                encrypted_path
            )
            
            print("Encryption completed")


            sha256_hash = generate_sha256(
                encrypted_path
            )    

            # Display AES key in terminal
            print("=" * 60)
            print("AES KEY :", key.hex())
            print("=" * 60)

            print("="* 60)
            print("SHA-256 HASH :",sha256_hash)
            print("=" * 60)

            # Delete original file
            os.remove(save_path)

            # Save file information into database
            file_id = execute_insert(
                """
                INSERT INTO files
                (
                    username,
                    original_filename,
                    encrypted_filename,
                    sha256_hash
                )
                VALUES
                (
                    ?, ?, ?, ?
                )
                """,
                (
                    session["username"],
                    filename,
                    filename + ".enc",
                    sha256_hash
                )
            )
            execute_query(
                """
                INSERT INTO file_keys
                (
                    file_id,
                     aes_key
                )
                 VALUES
                (
                    ?, ?
                )
                """,
                (
                    file_id,
                    key.hex()
                )
            )

            execute_query(
    """
    INSERT INTO security_logs
    (
        username,
        activity,
        ip_address
    )
    VALUES
    (
        ?, ?, ?
    )
    """,
    (
        session["username"],
        f"Uploaded encrypted file: {filename}",
        request.remote_addr
    )
)





            
                
                

            

            flash(
                "File Uploaded and Encrypted Successfully!",
                "success"
            )

            return redirect(url_for("upload"))

        else:

            flash(
                "Invalid file type.",
                "danger"
            )

            return redirect(request.url)

    return render_template("upload.html")


@app.route("/files")
def files():

    if "username" not in session:
        return redirect(url_for("login"))

    files = fetch_all(
        """
        SELECT *
        FROM files
        ORDER BY id DESC
        """
    )

    # ===============================
    # Module 7.5 - File Statistics
    # ===============================

    secure_files = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM files
        WHERE verification_status='Secure'
        """
    )["total"]

    tampered_files = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM files
        WHERE verification_status='Tampered'
        """
    )["total"]

    not_verified = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM files
        WHERE verification_status='Not Verified'
           OR verification_status IS NULL
        """
    )["total"]

    return render_template(
        "files.html",
        files=files,
        secure_files=secure_files,
        tampered_files=tampered_files,
        not_verified=not_verified
    )




@app.route("/download/<int:file_id>")
def download(file_id):

    if "username" not in session:
        return redirect(url_for("login"))

    file = fetch_one(
        """
        SELECT *
        FROM files
        WHERE id=?
        """,
        (file_id,)
    )

    if not file:

        flash("File not found.", "danger")
        return redirect(url_for("files"))

    key_data = fetch_one(
        """
        SELECT aes_key
        FROM file_keys
        WHERE file_id=?
        """,
        (file_id,)
    )

    if not key_data:

        flash("Encryption key not found.", "danger")
        return redirect(url_for("files"))

    aes_key = key_data["aes_key"]

    encrypted_path = os.path.join(
        Config.ENCRYPTED_FOLDER,
        file["encrypted_filename"]
    )

    decrypted_path = os.path.join(
        Config.UPLOAD_FOLDER,
        file["original_filename"]
    )

    decrypt_file(
        encrypted_path,
        decrypted_path,
        aes_key
    )

    execute_query(
        """
        INSERT INTO download_logs
        (
            username,
            file_name,
            ip_address
        )
        VALUES
        (?, ?, ?)
        """,
        (
            session["username"],
            file["original_filename"],
            request.remote_addr
        )
    )

    execute_query(
        """
        INSERT INTO security_logs
        (
            username,
            activity,
            ip_address
        )
        VALUES
        (?, ?, ?)
        """,
        (
            session["username"],
            "File Downloaded",
            request.remote_addr
        )
    )

    return send_file(
        decrypted_path,
        as_attachment=True,
        download_name=file["original_filename"]
    )



@app.route("/verify-file/<int:file_id>")
def verify_file_integrity(file_id):

    if "username" not in session:
        return redirect(url_for("login"))

    file = fetch_one(
        """
        SELECT *
        FROM files
        WHERE id=?
        """,
        (file_id,)
    )

    if not file:

        flash(
            "File not found.",
            "danger"
        )

        return redirect(url_for("files"))

    encrypted_path = os.path.join(
        app.config["ENCRYPTED_FOLDER"],
        file["encrypted_filename"]
    )

    if not os.path.exists(encrypted_path):

        flash(
            "Encrypted file not found.",
            "danger"
        )

        return redirect(url_for("files"))

    current_hash = generate_sha256(encrypted_path)

    original_hash = file["sha256_hash"]

    if current_hash == original_hash:

        status = "Secure"

        flash(
            "File Integrity Verified Successfully.",
            "success"
        )

    else:

        status = "Tampered"

        flash(
            "Warning! File Integrity Failed.",
            "danger"
        )

    execute_query(
        """
        UPDATE files
        SET verification_status=?
        WHERE id=?
        """,
        (
            status,
            file_id
        )
    )

    execute_query(
        """
        INSERT INTO security_logs
        (
            username,
            activity,
            ip_address
        )
        VALUES
        (
            ?, ?, ?
        )
        """,
        (
            session["username"],
            f"Verified file: {file['original_filename']} ({status})",
            request.remote_addr
        )
    )

    return redirect(url_for("files"))


@app.route("/verification-history")
def verification_history():

    if "username" not in session:
        return redirect(url_for("login"))

    logs = fetch_all(
        """
        SELECT
            username,
            activity,
            ip_address,
            log_time
        FROM security_logs
        WHERE activity IN
        (
            'File Integrity Verified',
            'File Integrity Failed'
        )
        ORDER BY log_time DESC
        """
    )

    return render_template(
        "verification_history.html",
        logs=logs
    )

@app.route("/export-verification-history")
def export_verification_history():

    if "username" not in session:
        return redirect(url_for("login"))

    logs = fetch_all(
        """
        SELECT
            username,
            activity,
            ip_address,
            log_time
        FROM security_logs
        WHERE activity IN
        (
            'File Integrity Verified',
            'File Integrity Failed'
        )
        ORDER BY log_time DESC
        """
    )

    import io
    import csv

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "Username",
        "Activity",
        "IP Address",
        "Date & Time"
    ])

    for log in logs:

        writer.writerow([
            log["username"],
            log["activity"],
            log["ip_address"],
            log["log_time"]
        ])

    response = make_response(output.getvalue())

    response.headers["Content-Disposition"] = \
        "attachment; filename=Verification_History.csv"

    response.headers["Content-Type"] = "text/csv"

    return response



@app.route("/delete-file/<int:file_id>")
def delete_file(file_id):

    if "username" not in session:
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    if session.get("role") != "Admin":
        flash("Access Denied.", "danger")
        return redirect(url_for("dashboard"))

    # Get file details
    file = fetch_one(
        "SELECT * FROM files WHERE id=?",
        (file_id,)
    )

    if not file:
        flash("File not found.", "danger")
        return redirect(url_for("files"))

    # Delete encrypted file from folder
    encrypted_path = os.path.join(
        app.config["ENCRYPTED_FOLDER"],
        file["encrypted_filename"]
    )

    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)

    # Delete decrypted copy if it exists
    download_path = os.path.join(
        app.config["DOWNLOAD_FOLDER"],
        file["original_filename"]
    )

    if os.path.exists(download_path):
        os.remove(download_path)

    # Delete AES key
    execute_query(
        "DELETE FROM file_keys WHERE file_id=?",
        (file_id,)
    )

    # Delete file record
    execute_query(
        "DELETE FROM files WHERE id=?",
        (file_id,)
    )

    # Log delete activity
    execute_query(
        """
        INSERT INTO security_logs
        (
            username,
            activity,
            ip_address
        )
        VALUES
        (
            ?, ?, ?
        )
        """,
        (
            session["username"],
            f"Deleted file: {file['original_filename']}",
            request.remote_addr
        )
    )

    flash("File deleted successfully.", "success")

    return redirect(url_for("files"))




@app.route("/verification-testing")
def verification_testing():

    if "username" not in session:
        return redirect(url_for("login"))

    return render_template("verification_testing.html")

@app.route("/module7-completed")
def module7_completed():

    if "username" not in session:
        return redirect(url_for("login"))

    return render_template("module7_completed.html")


@app.route("/download-analytics")
def download_analytics():

    if "username" not in session:
        return redirect(url_for("login"))

    daily = fetch_all("""
        SELECT
            DATE(download_time) AS day,
            COUNT(*) AS total
        FROM download_logs
        GROUP BY DATE(download_time)
        ORDER BY DATE(download_time)
    """)

    labels = []
    values = []

    for row in daily:
        labels.append(row["day"])
        values.append(row["total"])

    return render_template(
        "download_analytics.html",
        labels=labels,
        values=values
    )


@app.route("/download-report")
def download_report():

    if "username" not in session:
        return redirect(url_for("login"))

    total_downloads = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM download_logs
        """
    )

    today_downloads = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM download_logs
        WHERE DATE(download_time)=DATE('now')
        """
    )

    unique_users = fetch_one(
        """
        SELECT COUNT(DISTINCT username) AS total
        FROM download_logs
        """
    )

    recent_downloads = fetch_all(
        """
        SELECT *
        FROM download_logs
        ORDER BY download_time DESC
        LIMIT 10
        """
    )

    return render_template(
        "download_report.html",
        total_downloads=total_downloads["total"] if total_downloads else 0,
        today_downloads=today_downloads["total"] if today_downloads else 0,
        unique_users=unique_users["total"] if unique_users else 0,
        recent_downloads=recent_downloads
    )

@app.route("/export-download-report")
def export_download_report():

    if "username" not in session:
        return redirect(url_for("login"))

    downloads = fetch_all(
        """
        SELECT *
        FROM download_logs
        ORDER BY download_time DESC
        """
    )

    buffer = BytesIO()

    pdf = SimpleDocTemplate(buffer)

    elements = []

    styles = getSampleStyleSheet()

    title = Paragraph(
        "<b>Cloud Security - Download Report</b>",
        styles["Title"]
    )

    elements.append(title)

    elements.append(Paragraph("<br/><br/>", styles["Normal"]))

    data = [
        [
            "ID",
            "Username",
            "File Name",
            "IP Address",
            "Download Time"
        ]
    ]

    for row in downloads:

        data.append([
            row["id"],
            row["username"],
            row["file_name"],
            row["ip_address"],
            row["download_time"]
        ])

    table = Table(data)

    table.setStyle(TableStyle([

        ("BACKGROUND", (0,0), (-1,0), colors.darkblue),

        ("TEXTCOLOR", (0,0), (-1,0), colors.white),

        ("GRID",(0,0),(-1,-1),1,colors.black),

        ("BACKGROUND",(0,1),(-1,-1),colors.beige),

        ("ALIGN",(0,0),(-1,-1),"CENTER"),

        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),

        ("BOTTOMPADDING",(0,0),(-1,0),10)

    ]))

    elements.append(table)

    pdf.build(elements)

    buffer.seek(0)

    return send_file(

        buffer,

        as_attachment=True,

        download_name="Download_Report.pdf",

        mimetype="application/pdf"

    )

@app.route("/module8-completed")
def module8_completed():

    if "username" not in session:
        return redirect(url_for("login"))

    return render_template("module8_completed.html")


@app.route("/security-dashboard")
def security_dashboard():

    if "username" not in session:
        return redirect(url_for("login"))

    total_logs = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM security_logs
        """
    )["total"]

    total_logins = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM security_logs
        WHERE activity LIKE '%Login%'
        """
    )["total"]

    total_uploads = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM security_logs
        WHERE activity LIKE '%Uploaded%'
        """
    )["total"]

    total_downloads = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM security_logs
        WHERE activity LIKE '%Downloaded%'
        """
    )["total"]

    total_verifications = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM security_logs
        WHERE activity LIKE '%Verified%'
        """
    )["total"]

    recent_logs = fetch_all(
        """
        SELECT *
        FROM security_logs
        ORDER BY log_time DESC
        LIMIT 10
        """
    )

    return render_template(
        "security_dashboard.html",
        total_logs=total_logs,
        total_logins=total_logins,
        total_uploads=total_uploads,
        total_downloads=total_downloads,
        total_verifications=total_verifications,
        recent_logs=recent_logs
    )

@app.route("/security-analytics")
def security_analytics():

    if "username" not in session:
        return redirect(url_for("login"))

    total_logs = fetch_one("""
        SELECT COUNT(*) AS total
        FROM security_logs
    """)

    total_logins = fetch_one("""
        SELECT COUNT(*) AS total
        FROM security_logs
        WHERE activity LIKE '%Login%'
    """)

    total_uploads = fetch_one("""
        SELECT COUNT(*) AS total
        FROM security_logs
        WHERE activity LIKE '%Uploaded%'
    """)

    total_downloads = fetch_one("""
        SELECT COUNT(*) AS total
        FROM security_logs
        WHERE activity LIKE '%Download%'
    """)

    total_verified = fetch_one("""
        SELECT COUNT(*) AS total
        FROM security_logs
        WHERE activity LIKE '%Verified%'
    """)

    total_deleted = fetch_one("""
        SELECT COUNT(*) AS total
        FROM security_logs
        WHERE activity LIKE '%Deleted%'
    """)

    recent_logs = fetch_all("""
        SELECT *
        FROM security_logs
        ORDER BY id DESC
        LIMIT 10
    """)

    return render_template(
        "security_analytics.html",
        total_logs=total_logs["total"] if total_logs else 0,
        total_logins=total_logins["total"] if total_logins else 0,
        total_uploads=total_uploads["total"] if total_uploads else 0,
        total_downloads=total_downloads["total"] if total_downloads else 0,
        total_verified=total_verified["total"] if total_verified else 0,
        total_deleted=total_deleted["total"] if total_deleted else 0,
        recent_logs=recent_logs
    )

@app.route("/export-security-logs")
def export_security_logs():

    if "username" not in session:
        return redirect(url_for("login"))

    logs = fetch_all(
        """
        SELECT
            id,
            username,
            activity,
            ip_address,
            log_time
        FROM security_logs
        ORDER BY id DESC
        """
    )

    import io
    import csv

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Username",
        "Activity",
        "IP Address",
        "Date & Time"
    ])

    for log in logs:

        writer.writerow([
            log["id"],
            log["username"],
            log["activity"],
            log["ip_address"],
            log["log_time"]
        ])

    response = make_response(output.getvalue())

    response.headers["Content-Disposition"] = \
        "attachment; filename=Security_Logs_Report.csv"

    response.headers["Content-Type"] = "text/csv"

    return response

@app.route("/clear-security-logs")
def clear_security_logs():

    if "username" not in session:
        return redirect(url_for("login"))

    execute_query("""
        DELETE FROM security_logs
    """)

    flash("All Security Logs Cleared Successfully!", "success")

    return redirect(url_for("security_analytics"))

@app.route("/security-timeline")
def security_timeline():

    if "username" not in session:
        return redirect(url_for("login"))

    logs = fetch_all("""
        SELECT
            id,
            username,
            activity,
            ip_address,
            log_time
        FROM security_logs
        ORDER BY id DESC
        LIMIT 20
    """)

    return render_template(
        "security_timeline.html",
        logs=logs
    )

@app.route("/module9-completed")
def module9_completed():

    if "username" not in session:
        return redirect(url_for("login"))

    return render_template("module9_completed.html")


@app.route("/project-dashboard")
def project_dashboard():

    if "username" not in session:
        return redirect(url_for("login"))

    total_users = fetch_one("""
        SELECT COUNT(*) AS total
        FROM users
    """)

    total_files = fetch_one("""
        SELECT COUNT(*) AS total
        FROM files
    """)

    total_downloads = fetch_one("""
        SELECT COUNT(*) AS total
        FROM download_logs
    """)

    total_logs = fetch_one("""
        SELECT COUNT(*) AS total
        FROM security_logs
    """)

    total_verified = fetch_one("""
        SELECT COUNT(*) AS total
        FROM security_logs
        WHERE activity LIKE '%Verified%'
    """)

    total_deleted = fetch_one("""
        SELECT COUNT(*) AS total
        FROM security_logs
        WHERE activity LIKE '%Deleted%'
    """)

    return render_template(
        "project_dashboard.html",
        total_users=total_users["total"] if total_users else 0,
        total_files=total_files["total"] if total_files else 0,
        total_downloads=total_downloads["total"] if total_downloads else 0,
        total_logs=total_logs["total"] if total_logs else 0,
        total_verified=total_verified["total"] if total_verified else 0,
        total_deleted=total_deleted["total"] if total_deleted else 0
    )


@app.route("/system-statistics")
def system_statistics():

    if "username" not in session:
        return redirect(url_for("login"))

    total_users = fetch_one("""
        SELECT COUNT(*) AS total
        FROM users
    """)

    total_files = fetch_one("""
        SELECT COUNT(*) AS total
        FROM files
    """)

    total_downloads = fetch_one("""
        SELECT COUNT(*) AS total
        FROM download_logs
    """)

    total_logs = fetch_one("""
        SELECT COUNT(*) AS total
        FROM security_logs
    """)

    total_verified = fetch_one("""
        SELECT COUNT(*) AS total
        FROM security_logs
        WHERE activity LIKE '%Verified%'
    """)

    total_deleted = fetch_one("""
        SELECT COUNT(*) AS total
        FROM security_logs
        WHERE activity LIKE '%Deleted%'
    """)

    return render_template(
        "system_statistics.html",
        total_users=total_users["total"] if total_users else 0,
        total_files=total_files["total"] if total_files else 0,
        total_downloads=total_downloads["total"] if total_downloads else 0,
        total_logs=total_logs["total"] if total_logs else 0,
        total_verified=total_verified["total"] if total_verified else 0,
        total_deleted=total_deleted["total"] if total_deleted else 0
    )

@app.route("/project-report")
def project_report():

    if "username" not in session:
        return redirect(url_for("login"))

    total_users = fetch_one("SELECT COUNT(*) AS total FROM users")
    total_files = fetch_one("SELECT COUNT(*) AS total FROM files")
    total_downloads = fetch_one("SELECT COUNT(*) AS total FROM download_logs")
    total_logs = fetch_one("SELECT COUNT(*) AS total FROM security_logs")

    return render_template(
        "project_report.html",
        total_users=total_users["total"] if total_users else 0,
        total_files=total_files["total"] if total_files else 0,
        total_downloads=total_downloads["total"] if total_downloads else 0,
        total_logs=total_logs["total"] if total_logs else 0
    )

@app.route("/system-backup")
def system_backup():

    if "username" not in session:
        return redirect(url_for("login"))

    total_users = fetch_one("SELECT COUNT(*) AS total FROM users")
    total_files = fetch_one("SELECT COUNT(*) AS total FROM files")
    total_logs = fetch_one("SELECT COUNT(*) AS total FROM security_logs")

    return render_template(
        "system_backup.html",
        total_users=total_users["total"] if total_users else 0,
        total_files=total_files["total"] if total_files else 0,
        total_logs=total_logs["total"] if total_logs else 0
    )

@app.route("/project-completion")
def project_completion():

    if "username" not in session:
        return redirect(url_for("login"))

    return render_template("project_completion.html")

@app.route("/project-credits")
def project_credits():

    if "username" not in session:
        return redirect(url_for("login"))

    return render_template("project_credits.html")

@app.route("/thank-you")
def thank_you():

    if "username" not in session:
        return redirect(url_for("login"))

    return render_template("thank_you.html")


@app.route("/system-information")
def system_information():

    if "username" not in session:
        return redirect(url_for("login"))

    return render_template("system_information.html")

@app.route("/about-project")
def about_project():

    if "username" not in session:
        return redirect(url_for("login"))

    return render_template("about_project.html")


@app.route("/final-project")
def final_project():

    if "username" not in session:
        return redirect(url_for("login"))

    return render_template("final_project.html")









if __name__ == "__main__":
    app.run(debug=True)