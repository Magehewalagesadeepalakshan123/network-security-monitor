import os
import sqlite3


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


def get_connection():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    return connection


def init_db():

    connection = get_connection()

    cursor = connection.cursor()


    # Capture history table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS captures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total_packets INTEGER DEFAULT 0,
            tcp_packets INTEGER DEFAULT 0,
            udp_packets INTEGER DEFAULT 0,
            icmp_packets INTEGER DEFAULT 0,
            other_packets INTEGER DEFAULT 0,
            alert_count INTEGER DEFAULT 0
        )
        """
    )


    # Alerts table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            capture_id INTEGER NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (capture_id)
            REFERENCES captures(id)
        )
        """
    )


    connection.commit()
    connection.close()


def save_analysis(
    filename,
    stored_filename,
    statistics,
    alerts
):

    connection = get_connection()

    cursor = connection.cursor()


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
            alert_count
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            filename,
            stored_filename,
            statistics["total"],
            statistics["tcp"],
            statistics["udp"],
            statistics["icmp"],
            statistics["other"],
            len(alerts)
        )
    )


    capture_id = cursor.lastrowid


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


def get_dashboard_data():

    connection = get_connection()


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
            ) AS total_alerts

        FROM captures
        """
    ).fetchone()


    severity_rows = connection.execute(
        """
        SELECT
            severity,
            COUNT(*) AS count

        FROM alerts

        GROUP BY severity
        """
    ).fetchall()


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

        severity_data[
            row["severity"].upper()
        ] = row["count"]


    return (
        summary,
        severity_data,
        recent_captures
    )


def get_all_alerts(severity=None):

    connection = get_connection()

    if severity:

        alerts = connection.execute(
            """
            SELECT
                alerts.*,
                captures.filename
            FROM alerts

            JOIN captures
                ON alerts.capture_id = captures.id

            WHERE UPPER(alerts.severity) = ?

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
                ON alerts.capture_id = captures.id

            ORDER BY alerts.id DESC
            """
        ).fetchall()

    connection.close()

    return alerts



def get_capture_by_id(capture_id):

    connection = get_connection()

    capture = connection.execute(
        """
        SELECT *
        FROM captures
        WHERE id = ?
        """,
        (capture_id,)
    ).fetchone()

    connection.close()

    return capture


def get_alerts_by_capture(capture_id):

    connection = get_connection()

    alerts = connection.execute(
        """
        SELECT *
        FROM alerts
        WHERE capture_id = ?
        ORDER BY id DESC
        """,
        (capture_id,)
    ).fetchall()

    connection.close()

    return alerts


def delete_capture(capture_id):

    connection = get_connection()

    # Get capture first
    capture = connection.execute(
        """
        SELECT *
        FROM captures
        WHERE id = ?
        """,
        (capture_id,)
    ).fetchone()

    if capture is None:
        connection.close()
        return None

    # Delete related alerts first
    connection.execute(
        """
        DELETE FROM alerts
        WHERE capture_id = ?
        """,
        (capture_id,)
    )

    # Delete capture record
    connection.execute(
        """
        DELETE FROM captures
        WHERE id = ?
        """,
        (capture_id,)
    )

    connection.commit()
    connection.close()

    return capture