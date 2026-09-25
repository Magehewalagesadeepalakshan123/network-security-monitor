import os
import random

import joblib
import numpy as np

from sklearn.ensemble import IsolationForest


# ===================================================
# Project Paths
# ===================================================

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

PROJECT_DIR = os.path.dirname(
    CURRENT_DIR
)

MODEL_FOLDER = os.path.join(
    PROJECT_DIR,
    "models"
)

MODEL_PATH = os.path.join(
    MODEL_FOLDER,
    "anomaly_model.joblib"
)


os.makedirs(
    MODEL_FOLDER,
    exist_ok=True
)


# ===================================================
# Synthetic Training Data
#
# Used for prototype AI anomaly detection.
# ===================================================

training_data = []


for _ in range(300):

    total_packets = random.randint(
        20,
        600
    )

    tcp_ratio = random.uniform(
        0.30,
        0.80
    )

    udp_ratio = random.uniform(
        0.05,
        0.45
    )

    icmp_ratio = random.uniform(
        0.00,
        0.10
    )


    ratio_total = (
        tcp_ratio
        + udp_ratio
        + icmp_ratio
    )


    if ratio_total > 1:

        tcp_ratio = (
            tcp_ratio
            / ratio_total
        )

        udp_ratio = (
            udp_ratio
            / ratio_total
        )

        icmp_ratio = (
            icmp_ratio
            / ratio_total
        )


    tcp_packets = int(
        total_packets
        * tcp_ratio
    )


    udp_packets = int(
        total_packets
        * udp_ratio
    )


    icmp_packets = int(
        total_packets
        * icmp_ratio
    )


    other_packets = max(
        total_packets
        - tcp_packets
        - udp_packets
        - icmp_packets,
        0
    )


    unique_source_ips = random.randint(
        1,
        8
    )


    unique_destination_ips = random.randint(
        1,
        15
    )


    unique_destination_ports = random.randint(
        1,
        15
    )


    average_packet_size = random.uniform(
        60,
        900
    )


    maximum_packet_size = random.uniform(
        max(
            average_packet_size,
            100
        ),
        1500
    )


    row = [

        total_packets,

        tcp_packets,

        udp_packets,

        icmp_packets,

        other_packets,

        tcp_ratio,

        udp_ratio,

        icmp_ratio,

        unique_source_ips,

        unique_destination_ips,

        unique_destination_ports,

        average_packet_size,

        maximum_packet_size

    ]


    training_data.append(
        row
    )


# ===================================================
# Convert to NumPy Array
# ===================================================

X = np.array(
    training_data,
    dtype=float
)


# ===================================================
# Create Isolation Forest Model
# ===================================================

model = IsolationForest(

    n_estimators=200,

    contamination=0.08,

    random_state=42
)


# ===================================================
# Train Model
# ===================================================

model.fit(
    X
)


# ===================================================
# Save Model
# ===================================================

joblib.dump(
    model,
    MODEL_PATH
)


print(
    "AI anomaly model trained successfully."
)

print(
    "Training samples:",
    len(training_data)
)

print(
    "Model saved to:"
)

print(
    MODEL_PATH
)