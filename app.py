import os
import uuid

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash
)

from werkzeug.utils import secure_filename

from analyzer import analyze_capture
from detector import detect_suspicious_activity

from database import (
    init_db,
    save_analysis,
    get_capture_history
)


app = Flask(__name__)

app.secret_key = "network-security-project-secret-key"


# ---------------------------------------------------
# Initialize Database
# ---------------------------------------------------

init_db()


# ---------------------------------------------------
# Upload Configuration
# ---------------------------------------------------

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

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Maximum file size = 50 MB
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024


# Create uploads folder automatically
os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)


# ---------------------------------------------------
# Check File Extension
# ---------------------------------------------------

def allowed_file(filename):

    return (
        "." in filename
        and
        filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# ---------------------------------------------------
# Home Page
# ---------------------------------------------------

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ---------------------------------------------------
# Upload + Analyze
# ---------------------------------------------------

@app.route(
    "/upload",
    methods=["GET", "POST"]
)
def upload():

    if request.method == "POST":

        print("POST request received")


        # Check if file field exists
        if "capture_file" not in request.files:

            flash(
                "No file was received."
            )

            return redirect(
                request.url
            )


        file = request.files[
            "capture_file"
        ]


        # Check filename
        if file.filename == "":

            flash(
                "Please select a file."
            )

            return redirect(
                request.url
            )


        # Validate extension
        if not allowed_file(
            file.filename
        ):

            flash(
                "Invalid file type. "
                "Please select a .pcap or .pcapng file."
            )

            return redirect(
                request.url
            )


        # Clean original filename
        original_filename = secure_filename(
            file.filename
        )


        # Give uploaded file a unique name
        unique_filename = (
            str(uuid.uuid4())
            + "_"
            + original_filename
        )


        # Full path
        file_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            unique_filename
        )


        # ---------------------------------------------------
        # Save File
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

            # Analyze packets
            statistics, packet_details = analyze_capture(
                file_path
            )


            # Detect suspicious activity
            alerts = detect_suspicious_activity(
                packet_details
            )


            # Save analysis into SQLite database
            capture_id = save_analysis(
                original_filename,
                unique_filename,
                statistics,
                alerts
            )


            print(
                "Analysis completed successfully"
            )

            print(
                "Security alerts detected:",
                len(alerts)
            )

            print(
                "Saved capture ID:",
                capture_id
            )


        except Exception as error:

            print(
                "Analysis error:",
                error
            )

            flash(
                "The file was uploaded, "
                "but it could not be analyzed. "
                "Please use a valid PCAP or PCAPNG file."
            )

            return redirect(
                request.url
            )


        # ---------------------------------------------------
        # Show Results
        # ---------------------------------------------------

        return render_template(
            "result.html",
            filename=original_filename,
            statistics=statistics,
            packets=packet_details,
            alerts=alerts,
            capture_id=capture_id
        )


    return render_template(
        "upload.html"
    )


# ---------------------------------------------------
# Analysis History
# ---------------------------------------------------

@app.route("/history")
def history():

    captures = get_capture_history()

    return render_template(
        "history.html",
        captures=captures
    )


# ---------------------------------------------------
# Start Application
# ---------------------------------------------------

if __name__ == "__main__":

    app.run(
        debug=True
    )