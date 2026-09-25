import os

import joblib
import numpy as np


# ===================================================
# Model Path
# ===================================================

BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "anomaly_model.joblib"
)


# ===================================================
# Feature Order
#
# Must be exactly the same order used
# when training the model.
# ===================================================

FEATURE_ORDER = [
    "total_packets",
    "tcp_packets",
    "udp_packets",
    "icmp_packets",
    "other_packets",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "unique_source_ips",
    "unique_destination_ips",
    "unique_destination_ports",
    "average_packet_size",
    "maximum_packet_size"
]


# ===================================================
# Load AI Model
# ===================================================

def load_ai_model():

    if not os.path.exists(
        MODEL_PATH
    ):

        return None

    try:

        model = joblib.load(
            MODEL_PATH
        )

        return model

    except Exception as error:

        print(
            "AI model loading error:",
            error
        )

        return None


# ===================================================
# Convert Features to AI Input
# ===================================================

def features_to_array(
    features
):

    values = []

    for feature_name in FEATURE_ORDER:

        value = features.get(
            feature_name,
            0
        )

        values.append(
            float(value)
        )


    return np.array(
        [
            values
        ],
        dtype=float
    )


# ===================================================
# Calculate Display Anomaly Score
#
# This is a display score for the prototype.
# It is NOT a probability of an attack.
# ===================================================

def calculate_display_score(
    raw_score
):

    # Isolation Forest:
    #
    # Positive score = more normal
    # Negative score = more anomalous

    if raw_score >= 0:

        score = max(
            0,
            50 - (raw_score * 100)
        )

    else:

        score = min(
            100,
            50 + (abs(raw_score) * 200)
        )


    return round(
        score,
        2
    )


# ===================================================
# Determine Risk Level
# ===================================================

def get_risk_level(
    prediction,
    anomaly_score
):

    if prediction != -1:

        return "LOW"


    if anomaly_score >= 75:

        return "HIGH"


    if anomaly_score >= 55:

        return "MEDIUM"


    return "LOW"


# ===================================================
# AI Anomaly Detection
# ===================================================

def detect_ai_anomaly(
    features
):

    model = load_ai_model()


    # ---------------------------------------------------
    # Model Missing
    # ---------------------------------------------------

    if model is None:

        return {
            "available": False,
            "prediction": "MODEL NOT AVAILABLE",
            "is_anomaly": False,
            "anomaly_score": 0,
            "risk": "UNKNOWN",
            "raw_score": 0
        }


    # ---------------------------------------------------
    # Convert Features
    # ---------------------------------------------------

    try:

        X = features_to_array(
            features
        )


        # Isolation Forest:
        #
        #  1 = Normal
        # -1 = Anomaly

        prediction = int(
            model.predict(
                X
            )[0]
        )


        raw_score = float(
            model.decision_function(
                X
            )[0]
        )


        anomaly_score = (
            calculate_display_score(
                raw_score
            )
        )


        is_anomaly = (
            prediction == -1
        )


        risk = get_risk_level(
            prediction,
            anomaly_score
        )


        if is_anomaly:

            status = (
                "ANOMALOUS TRAFFIC"
            )

        else:

            status = (
                "NORMAL TRAFFIC"
            )


        return {
            "available": True,
            "prediction": status,
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "risk": risk,
            "raw_score": round(
                raw_score,
                6
            )
        }


    except Exception as error:

        print(
            "AI detection error:",
            error
        )


        return {
            "available": False,
            "prediction": "AI ANALYSIS ERROR",
            "is_anomaly": False,
            "anomaly_score": 0,
            "risk": "UNKNOWN",
            "raw_score": 0
        }