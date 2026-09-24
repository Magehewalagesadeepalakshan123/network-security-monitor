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