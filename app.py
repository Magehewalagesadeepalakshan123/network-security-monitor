import os
import uuid

from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename

from analyzer import analyze_capture

from detector import (
    detect_suspicious_activity
)


# ===================================================
# AI Imports
# ===================================================

from feature_extractor import (
    extract_ai_features
)

from ai_detector import (
    detect_ai_anomaly
)


# ===================================================
# Database Imports
# ===================================================

from database import (
    init_db,
    save_analysis,
    get_capture_history,
    get_user_capture_history,
    get_dashboard_data,
    get_all_alerts,
    get_user_alerts,
    get_capture_by_id,
    get_user_capture_by_id,
    get_alerts_by_capture,
    delete_capture,
    get_user_by_username,
    create_user,
    update_user_role
)


# ===================================================
# Flask Application
# ===================================================

app = Flask(__name__)

app.secret_key = (
    "network-security-project-secret-key"
)


# ===================================================
# Initialize Database
# ===================================================

init_db()


# ===================================================
# Create Default Accounts
# ===================================================

def create_default_accounts():

    # ---------------------------------------------------
    # ADMIN
    # ---------------------------------------------------

    admin = get_user_by_username(
        "admin"
    )


    if admin is None:

        admin_password_hash = (
            generate_password_hash(
                "Admin@123"
            )
        )

        create_user(
            "admin",
            admin_password_hash,
            "admin"
        )

        print(
            "Default admin account created."
        )


    else:

        if admin["role"] != "admin":

            update_user_role(
                "admin",
                "admin"
            )

            print(
                "Admin role updated."
            )


    # ---------------------------------------------------
    # NORMAL USER
    # ---------------------------------------------------

    normal_user = get_user_by_username(
        "user"
    )


    if normal_user is None:

        user_password_hash = (
            generate_password_hash(
                "User@123"
            )
        )

        create_user(
            "user",
            user_password_hash,
            "user"
        )

        print(
            "Default user account created."
        )


create_default_accounts()


# ===================================================
# Login Required
# ===================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            flash(
                "Please login to continue."
            )

            return redirect(
                url_for("login")
            )


        return function(
            *args,
            **kwargs
        )


    return wrapper


# ===================================================
# Admin Required
# ===================================================

def admin_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        # ---------------------------------------------------
        # Not Logged In
        # ---------------------------------------------------

        if "user_id" not in session:

            flash(
                "Please login to continue."
            )

            return redirect(
                url_for("login")
            )


        # ---------------------------------------------------
        # Logged In But Not Admin
        # ---------------------------------------------------

        if session.get("role") != "admin":

            flash(
                "You do not have permission "
                "to access the admin area."
            )

            return redirect(
                url_for("home")
            )


        return function(
            *args,
            **kwargs
        )


    return wrapper


# ===================================================
# User Required
# ===================================================

def user_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        # ---------------------------------------------------
        # Not Logged In
        # ---------------------------------------------------

        if "user_id" not in session:

            flash(
                "Please login to continue."
            )

            return redirect(
                url_for("login")
            )


        # ---------------------------------------------------
        # Admin Uses Admin Dashboard
        # ---------------------------------------------------

        if session.get("role") == "admin":

            return redirect(
                url_for("dashboard")
            )


        # ---------------------------------------------------
        # Only Normal User Role Allowed
        # ---------------------------------------------------

        if session.get("role") != "user":

            session.clear()

            flash(
                "Invalid user role."
            )

            return redirect(
                url_for("login")
            )


        return function(
            *args,
            **kwargs
        )


    return wrapper


# ===================================================
# Upload Configuration
# ===================================================

BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)

UPLOAD_FOLDER = os.path.join(
    BASE_DIR,
    "uploads"
)

ALLOWED_EXTENSIONS = {
    "pcap",
    "pcapng"
}


app.config[
    "UPLOAD_FOLDER"
] = UPLOAD_FOLDER


# Maximum upload size = 50 MB
app.config[
    "MAX_CONTENT_LENGTH"
] = 50 * 1024 * 1024


# Create uploads folder
os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)


# ===================================================
# Validate File Extension
# ===================================================

def allowed_file(filename):

    return (
        "." in filename
        and
        filename.rsplit(
            ".",
            1
        )[1].lower()
        in ALLOWED_EXTENSIONS
    )


# ===================================================
# Start Page
#
# http://127.0.0.1:5000/
#
# Always starts at Login
# ===================================================

@app.route("/")
def start_page():

    session.clear()

    return redirect(
        url_for("login")
    )


# ===================================================
# User Home Page
# USER ONLY
# ===================================================

@app.route("/home")
@user_required
def home():

    return render_template(
        "index.html"
    )


# ===================================================
# Login
# ===================================================

@app.route(
    "/login",
    methods=[
        "GET",
        "POST"
    ]
)
def login():

    # ---------------------------------------------------
    # Already Logged In
    # ---------------------------------------------------

    if "user_id" in session:

        # Admin
        if session.get("role") == "admin":

            return redirect(
                url_for("dashboard")
            )


        # Normal User
        if session.get("role") == "user":

            return redirect(
                url_for("home")
            )


        session.clear()


    # ---------------------------------------------------
    # Login Form Submitted
    # ---------------------------------------------------

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()


        password = request.form.get(
            "password",
            ""
        )


        # Find user
        user = get_user_by_username(
            username
        )


        # ---------------------------------------------------
        # Verify Username + Password
        # ---------------------------------------------------

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            # Clear previous session
            session.clear()


            # Save user session
            session[
                "user_id"
            ] = user["id"]

            session[
                "username"
            ] = user["username"]

            session[
                "role"
            ] = user["role"]


            # ---------------------------------------------------
            # ADMIN LOGIN
            # ---------------------------------------------------

            if user["role"] == "admin":

                flash(
                    "Admin login successful."
                )

                return redirect(
                    url_for("dashboard")
                )


            # ---------------------------------------------------
            # USER LOGIN
            # ---------------------------------------------------

            if user["role"] == "user":

                flash(
                    "Login successful."
                )

                return redirect(
                    url_for("home")
                )


            # ---------------------------------------------------
            # Unknown Role
            # ---------------------------------------------------

            session.clear()

            flash(
                "Your account role is not valid."
            )

            return redirect(
                url_for("login")
            )


        # ---------------------------------------------------
        # Invalid Credentials
        # ---------------------------------------------------

        flash(
            "Invalid username or password."
        )


    return render_template(
        "login.html"
    )


# ===================================================
# Logout
# ===================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out successfully."
    )

    return redirect(
        url_for("login")
    )


# ===================================================
# Upload + Analyze
#
# ADMIN + USER
# ===================================================

@app.route(
    "/upload",
    methods=[
        "GET",
        "POST"
    ]
)
@login_required
def upload():

    if request.method == "POST":

        print(
            "POST request received"
        )


        # ---------------------------------------------------
        # Check File Field
        # ---------------------------------------------------

        if (
            "capture_file"
            not in request.files
        ):

            flash(
                "No file was received."
            )

            return redirect(
                request.url
            )


        file = request.files[
            "capture_file"
        ]


        # ---------------------------------------------------
        # Check Filename
        # ---------------------------------------------------

        if file.filename == "":

            flash(
                "Please select a file."
            )

            return redirect(
                request.url
            )


        # ---------------------------------------------------
        # Validate Extension
        # ---------------------------------------------------

        if not allowed_file(
            file.filename
        ):

            flash(
                "Invalid file type. "
                "Please select a .pcap "
                "or .pcapng file."
            )

            return redirect(
                request.url
            )


        # ---------------------------------------------------
        # Create Safe Unique Filename
        # ---------------------------------------------------

        original_filename = secure_filename(
            file.filename
        )


        unique_filename = (
            str(
                uuid.uuid4()
            )
            + "_"
            + original_filename
        )


        file_path = os.path.join(
            app.config[
                "UPLOAD_FOLDER"
            ],
            unique_filename
        )


        # ---------------------------------------------------
        # Save Uploaded File
        # ---------------------------------------------------

        try:

            file.save(
                file_path
            )


            print(
                "File saved successfully:"
            )


            print(
                file_path
            )


        except Exception as error:

            print(
                "File save error:",
                error
            )


            flash(
                "The file could not be saved."
            )


            return redirect(
                request.url
            )


        # ---------------------------------------------------
        # Analyze Capture
        # ---------------------------------------------------

        try:

            # ===================================================
            # 1. Packet Analysis
            # ===================================================

            (
                statistics,
                packet_details
            ) = analyze_capture(
                file_path
            )


            # ===================================================
            # 2. Rule-Based Detection
            # ===================================================

            alerts = (
                detect_suspicious_activity(
                    packet_details
                )
            )


            # ===================================================
            # 3. AI Feature Extraction
            # ===================================================

            ai_features = extract_ai_features(
                statistics,
                packet_details
            )


            print(
                "AI Features:"
            )


            print(
                ai_features
            )


            # ===================================================
            # 4. AI Anomaly Detection
            # ===================================================

            ai_result = detect_ai_anomaly(
                ai_features
            )


            print(
                "AI Result:"
            )


            print(
                ai_result
            )


            # ===================================================
            # 5. Save Analysis + AI Results to SQLite
            # ===================================================

            capture_id = save_analysis(
                original_filename,
                unique_filename,
                statistics,
                alerts,
                session["user_id"],
                ai_result
            )


            print(
                "Analysis completed successfully."
            )


            print(
                "Security alerts detected:",
                len(
                    alerts
                )
            )


            print(
                "Capture ID:",
                capture_id
            )


            print(
                "Uploaded by User ID:",
                session["user_id"]
            )


            print(
                "AI Prediction:",
                ai_result.get(
                    "prediction"
                )
            )


            print(
                "AI Anomaly Score:",
                ai_result.get(
                    "anomaly_score"
                )
            )


            print(
                "AI Risk:",
                ai_result.get(
                    "risk"
                )
            )


        except Exception as error:

            print(
                "Analysis error:",
                error
            )


            # ---------------------------------------------------
            # Remove File if Analysis Failed
            # ---------------------------------------------------

            try:

                if os.path.exists(
                    file_path
                ):

                    os.remove(
                        file_path
                    )


            except Exception as delete_error:

                print(
                    "Failed to remove invalid file:",
                    delete_error
                )


            flash(
                "The file was uploaded, "
                "but it could not be analyzed. "
                "Please use a valid PCAP "
                "or PCAPNG file."
            )


            return redirect(
                request.url
            )


        # ---------------------------------------------------
        # Show Analysis Result
        # ---------------------------------------------------

        return render_template(
            "result.html",
            filename=original_filename,
            statistics=statistics,
            packets=packet_details,
            alerts=alerts,
            capture_id=capture_id,
            ai_result=ai_result
        )


    return render_template(
        "upload.html"
    )


# ===================================================
# Admin Dashboard
# ADMIN ONLY
# ===================================================

@app.route(
    "/dashboard"
)
@admin_required
def dashboard():

    (
        summary,
        severity_data,
        recent_captures
    ) = get_dashboard_data()


    return render_template(
        "dashboard.html",
        summary=summary,
        severity_data=severity_data,
        recent_captures=recent_captures
    )


# ===================================================
# Analysis History
#
# ADMIN:
# See all capture history
#
# USER:
# See only own capture history
# ===================================================

@app.route(
    "/history"
)
@login_required
def history():

    # ---------------------------------------------------
    # Admin -> All History
    # ---------------------------------------------------

    if session.get("role") == "admin":

        captures = get_capture_history()


    # ---------------------------------------------------
    # User -> Own History
    # ---------------------------------------------------

    else:

        captures = get_user_capture_history(
            session["user_id"]
        )


    return render_template(
        "history.html",
        captures=captures
    )


# ===================================================
# Security Alerts
#
# ADMIN:
# See all alerts
#
# USER:
# See only own alerts
# ===================================================

@app.route(
    "/alerts"
)
@login_required
def alerts():

    severity = request.args.get(
        "severity"
    )


    # ---------------------------------------------------
    # Admin -> All Alerts
    # ---------------------------------------------------

    if session.get("role") == "admin":

        alert_records = get_all_alerts(
            severity
        )


    # ---------------------------------------------------
    # User -> Own Alerts
    # ---------------------------------------------------

    else:

        alert_records = get_user_alerts(
            session["user_id"],
            severity
        )


    return render_template(
        "alerts.html",
        alerts=alert_records,
        selected_severity=severity
    )


# ===================================================
# Analysis Details
#
# ADMIN:
# Can view any analysis
#
# USER:
# Can view only own analysis
# ===================================================

@app.route(
    "/analysis/<int:capture_id>"
)
@login_required
def analysis_detail(
    capture_id
):

    # ---------------------------------------------------
    # Admin
    # ---------------------------------------------------

    if session.get("role") == "admin":

        capture = get_capture_by_id(
            capture_id
        )


    # ---------------------------------------------------
    # User
    # ---------------------------------------------------

    else:

        capture = get_user_capture_by_id(
            capture_id,
            session["user_id"]
        )


    # ---------------------------------------------------
    # Record Not Found / Permission Denied
    # ---------------------------------------------------

    if capture is None:

        flash(
            "Analysis record not found "
            "or you do not have permission "
            "to view it."
        )

        return redirect(
            url_for("history")
        )


    # ---------------------------------------------------
    # Get Related Rule Alerts
    # ---------------------------------------------------

    alert_records = get_alerts_by_capture(
        capture_id
    )


    return render_template(
        "analysis_detail.html",
        capture=capture,
        alerts=alert_records
    )


# ===================================================
# Delete Analysis
#
# ADMIN ONLY
# ===================================================

@app.route(
    "/analysis/<int:capture_id>/delete",
    methods=[
        "POST"
    ]
)
@admin_required
def delete_analysis(
    capture_id
):

    capture = delete_capture(
        capture_id
    )


    # ---------------------------------------------------
    # Capture Doesn't Exist
    # ---------------------------------------------------

    if capture is None:

        flash(
            "Analysis record not found."
        )

        return redirect(
            url_for("history")
        )


    stored_filename = capture[
        "stored_filename"
    ]


    file_path = os.path.join(
        app.config[
            "UPLOAD_FOLDER"
        ],
        stored_filename
    )


    # ---------------------------------------------------
    # Delete Uploaded Capture File
    # ---------------------------------------------------

    try:

        if os.path.exists(
            file_path
        ):

            os.remove(
                file_path
            )


    except Exception as error:

        print(
            "File deletion error:",
            error
        )


    flash(
        "Analysis deleted successfully."
    )


    return redirect(
        url_for("history")
    )


# ===================================================
# Start Application
# ===================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )