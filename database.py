import os
import sqlite3


# ===================================================
# DATABASE CONFIGURATION
# ===================================================

BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)

DATABASE_FOLDER = os.path.join(
    BASE_DIR,
    "database"
)

DATABASE_PATH = os.path.join(
    DATABASE_FOLDER,
    "security.db"
)

os.makedirs(
    DATABASE_FOLDER,
    exist_ok=True
)


# ===================================================
# DATABASE CONNECTION
# ===================================================

def get_connection():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection


# ===================================================
# INITIALIZE DATABASE
# ===================================================

def init_db():

    connection = get_connection()

    cursor = connection.cursor()


    # ===================================================
    # USERS TABLE
    # ===================================================

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


    # ===================================================
    # UPGRADE OLD USERS TABLE
    # ===================================================

    user_columns = cursor.execute(
        """
        PRAGMA table_info(users)
        """
    ).fetchall()

    user_column_names = [
        column["name"]
        for column in user_columns
    ]

    if "role" not in user_column_names:

        cursor.execute(
            """
            ALTER TABLE users
            ADD COLUMN role TEXT
            NOT NULL DEFAULT 'user'
            """
        )

        print(
            "Database upgraded: "
            "role column added to users."
        )


    # ===================================================
    # CAPTURES TABLE
    # ===================================================

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS captures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            filename TEXT NOT NULL,

            stored_filename TEXT NOT NULL,

            upload_date TIMESTAMP
            DEFAULT CURRENT_TIMESTAMP,

            total_packets INTEGER DEFAULT 0,

            tcp_packets INTEGER DEFAULT 0,

            udp_packets INTEGER DEFAULT 0,

            icmp_packets INTEGER DEFAULT 0,

            other_packets INTEGER DEFAULT 0,

            alert_count INTEGER DEFAULT 0,

            user_id INTEGER,

            ai_prediction TEXT,

            ai_anomaly_score REAL,

            ai_risk TEXT,

            FOREIGN KEY (user_id)
            REFERENCES users(id)
        )
        """
    )


    # ===================================================
    # UPGRADE OLD CAPTURES TABLE
    # ===================================================

    capture_columns = cursor.execute(
        """
        PRAGMA table_info(captures)
        """
    ).fetchall()

    capture_column_names = [
        column["name"]
        for column in capture_columns
    ]


    # ---------------------------------------------------
    # Add user_id
    # ---------------------------------------------------

    if "user_id" not in capture_column_names:

        cursor.execute(
            """
            ALTER TABLE captures
            ADD COLUMN user_id INTEGER
            """
        )

        print(
            "Database upgraded: "
            "user_id column added."
        )


    # ---------------------------------------------------
    # Add AI Prediction
    # ---------------------------------------------------

    if "ai_prediction" not in capture_column_names:

        cursor.execute(
            """
            ALTER TABLE captures
            ADD COLUMN ai_prediction TEXT
            """
        )

        print(
            "Database upgraded: "
            "ai_prediction column added."
        )


    # ---------------------------------------------------
    # Add AI Anomaly Score
    # ---------------------------------------------------

    if "ai_anomaly_score" not in capture_column_names:

        cursor.execute(
            """
            ALTER TABLE captures
            ADD COLUMN ai_anomaly_score REAL
            """
        )

        print(
            "Database upgraded: "
            "ai_anomaly_score column added."
        )


    # ---------------------------------------------------
    # Add AI Risk
    # ---------------------------------------------------

    if "ai_risk" not in capture_column_names:

        cursor.execute(
            """
            ALTER TABLE captures
            ADD COLUMN ai_risk TEXT
            """
        )

        print(
            "Database upgraded: "
            "ai_risk column added."
        )


    # ===================================================
    # ALERTS TABLE
    # ===================================================

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            capture_id INTEGER NOT NULL,

            alert_type TEXT NOT NULL,

            severity TEXT NOT NULL,

            source_ip TEXT,

            description TEXT,

            created_at TIMESTAMP
            DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (capture_id)
            REFERENCES captures(id)
        )
        """
    )


    connection.commit()

    connection.close()


# ===================================================
# SAVE ANALYSIS
# ===================================================

def save_analysis(
    filename,
    stored_filename,
    statistics,
    alerts,
    user_id,
    ai_result=None
):

    connection = get_connection()

    cursor = connection.cursor()


    # ===================================================
    # AI VALUES
    # ===================================================

    ai_prediction = None
    ai_anomaly_score = None
    ai_risk = None


    if ai_result:

        ai_prediction = ai_result.get(
            "prediction"
        )

        ai_anomaly_score = ai_result.get(
            "anomaly_score"
        )

        ai_risk = ai_result.get(
            "risk"
        )


    # ===================================================
    # SAVE CAPTURE
    # ===================================================

    cursor.execute(
        """
        INSERT INTO captures (
            filename,
            stored_filename,
            total_packets,
            tcp_packets,
            udp_packets,
            icmp_packets,
            other_packets,
            alert_count,
            user_id,
            ai_prediction,
            ai_anomaly_score,
            ai_risk
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            filename,
            stored_filename,
            statistics["total"],
            statistics["tcp"],
            statistics["udp"],
            statistics["icmp"],
            statistics["other"],
            len(alerts),
            user_id,
            ai_prediction,
            ai_anomaly_score,
            ai_risk
        )
    )


    capture_id = cursor.lastrowid


    # ===================================================
    # SAVE SECURITY ALERTS
    # ===================================================

    for alert in alerts:

        cursor.execute(
            """
            INSERT INTO alerts (
                capture_id,
                alert_type,
                severity,
                source_ip,
                description
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                capture_id,
                alert["alert_type"],
                alert["severity"],
                alert["source_ip"],
                alert["description"]
            )
        )


    connection.commit()

    connection.close()

    return capture_id


# ===================================================
# ADMIN - GET ALL CAPTURE HISTORY
# ===================================================

def get_capture_history():

    connection = get_connection()

    captures = connection.execute(
        """
        SELECT *
        FROM captures
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return captures


# ===================================================
# USER - GET OWN CAPTURE HISTORY
# ===================================================

def get_user_capture_history(
    user_id
):

    connection = get_connection()

    captures = connection.execute(
        """
        SELECT *
        FROM captures
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (
            user_id,
        )
    ).fetchall()

    connection.close()

    return captures


# ===================================================
# ADMIN DASHBOARD DATA
# ===================================================

def get_dashboard_data():

    connection = get_connection()


    # ===================================================
    # SUMMARY
    # ===================================================

    summary = connection.execute(
        """
        SELECT

            COUNT(*) AS total_analyses,

            COALESCE(
                SUM(total_packets),
                0
            ) AS total_packets,

            COALESCE(
                SUM(tcp_packets),
                0
            ) AS tcp_packets,

            COALESCE(
                SUM(udp_packets),
                0
            ) AS udp_packets,

            COALESCE(
                SUM(icmp_packets),
                0
            ) AS icmp_packets,

            COALESCE(
                SUM(other_packets),
                0
            ) AS other_packets,

            COALESCE(
                SUM(alert_count),
                0
            ) AS total_alerts,

            COALESCE(
                SUM(
                    CASE
                        WHEN ai_prediction =
                        'ANOMALOUS TRAFFIC'
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS ai_anomalies

        FROM captures
        """
    ).fetchone()


    # ===================================================
    # ALERT SEVERITY
    # ===================================================

    severity_rows = connection.execute(
        """
        SELECT
            severity,
            COUNT(*) AS count

        FROM alerts

        GROUP BY severity
        """
    ).fetchall()


    # ===================================================
    # RECENT CAPTURES
    # ===================================================

    recent_captures = connection.execute(
        """
        SELECT *
        FROM captures
        ORDER BY id DESC
        LIMIT 5
        """
    ).fetchall()


    connection.close()


    severity_data = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }


    for row in severity_rows:

        severity = row[
            "severity"
        ].upper()


        if severity in severity_data:

            severity_data[
                severity
            ] = row["count"]


    return (
        summary,
        severity_data,
        recent_captures
    )


# ===================================================
# ADMIN - GET ALL ALERTS
# ===================================================

def get_all_alerts(
    severity=None
):

    connection = get_connection()


    if severity:

        alerts = connection.execute(
            """
            SELECT
                alerts.*,
                captures.filename

            FROM alerts

            JOIN captures
                ON alerts.capture_id =
                   captures.id

            WHERE UPPER(
                alerts.severity
            ) = ?

            ORDER BY alerts.id DESC
            """,
            (
                severity.upper(),
            )
        ).fetchall()


    else:

        alerts = connection.execute(
            """
            SELECT
                alerts.*,
                captures.filename

            FROM alerts

            JOIN captures
                ON alerts.capture_id =
                   captures.id

            ORDER BY alerts.id DESC
            """
        ).fetchall()


    connection.close()

    return alerts


# ===================================================
# USER - GET OWN ALERTS
# ===================================================

def get_user_alerts(
    user_id,
    severity=None
):

    connection = get_connection()


    if severity:

        alerts = connection.execute(
            """
            SELECT
                alerts.*,
                captures.filename

            FROM alerts

            JOIN captures
                ON alerts.capture_id =
                   captures.id

            WHERE captures.user_id = ?

            AND UPPER(
                alerts.severity
            ) = ?

            ORDER BY alerts.id DESC
            """,
            (
                user_id,
                severity.upper()
            )
        ).fetchall()


    else:

        alerts = connection.execute(
            """
            SELECT
                alerts.*,
                captures.filename

            FROM alerts

            JOIN captures
                ON alerts.capture_id =
                   captures.id

            WHERE captures.user_id = ?

            ORDER BY alerts.id DESC
            """,
            (
                user_id,
            )
        ).fetchall()


    connection.close()

    return alerts


# ===================================================
# ADMIN - GET CAPTURE BY ID
# ===================================================

def get_capture_by_id(
    capture_id
):

    connection = get_connection()

    capture = connection.execute(
        """
        SELECT *
        FROM captures
        WHERE id = ?
        """,
        (
            capture_id,
        )
    ).fetchone()

    connection.close()

    return capture


# ===================================================
# USER - GET OWN CAPTURE BY ID
# ===================================================

def get_user_capture_by_id(
    capture_id,
    user_id
):

    connection = get_connection()

    capture = connection.execute(
        """
        SELECT *
        FROM captures

        WHERE id = ?

        AND user_id = ?
        """,
        (
            capture_id,
            user_id
        )
    ).fetchone()

    connection.close()

    return capture


# ===================================================
# GET ALERTS BY CAPTURE
# ===================================================

def get_alerts_by_capture(
    capture_id
):

    connection = get_connection()

    alerts = connection.execute(
        """
        SELECT *
        FROM alerts

        WHERE capture_id = ?

        ORDER BY id DESC
        """,
        (
            capture_id,
        )
    ).fetchall()

    connection.close()

    return alerts


# ===================================================
# DELETE CAPTURE
# ADMIN ONLY
# ===================================================

def delete_capture(
    capture_id
):

    connection = get_connection()


    # ---------------------------------------------------
    # Find Capture
    # ---------------------------------------------------

    capture = connection.execute(
        """
        SELECT *
        FROM captures

        WHERE id = ?
        """,
        (
            capture_id,
        )
    ).fetchone()


    if capture is None:

        connection.close()

        return None


    # ---------------------------------------------------
    # Delete Related Alerts
    # ---------------------------------------------------

    connection.execute(
        """
        DELETE FROM alerts

        WHERE capture_id = ?
        """,
        (
            capture_id,
        )
    )


    # ---------------------------------------------------
    # Delete Capture
    # ---------------------------------------------------

    connection.execute(
        """
        DELETE FROM captures

        WHERE id = ?
        """,
        (
            capture_id,
        )
    )


    connection.commit()

    connection.close()

    return capture


# ===================================================
# GET USER BY USERNAME
# ===================================================

def get_user_by_username(
    username
):

    connection = get_connection()

    user = connection.execute(
        """
        SELECT *
        FROM users

        WHERE username = ?
        """,
        (
            username,
        )
    ).fetchone()

    connection.close()

    return user


# ===================================================
# CREATE USER
# ===================================================

def create_user(
    username,
    password_hash,
    role="user"
):

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute(
        """
        INSERT INTO users (
            username,
            password_hash,
            role
        )
        VALUES (?, ?, ?)
        """,
        (
            username,
            password_hash,
            role
        )
    )


    connection.commit()

    connection.close()


# ===================================================
# UPDATE USER ROLE
# ===================================================

def update_user_role(
    username,
    role
):

    connection = get_connection()


    connection.execute(
        """
        UPDATE users

        SET role = ?

        WHERE username = ?
        """,
        (
            role,
            username
        )
    )


    connection.commit()

    connection.close()