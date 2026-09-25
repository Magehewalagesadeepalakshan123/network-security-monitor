# ===================================================
# AI Feature Extraction
# ===================================================


def extract_ai_features(
    statistics,
    packet_details
):

    # ---------------------------------------------------
    # Basic Packet Statistics
    # ---------------------------------------------------

    total_packets = statistics.get(
        "total",
        0
    )

    tcp_packets = statistics.get(
        "tcp",
        0
    )

    udp_packets = statistics.get(
        "udp",
        0
    )

    icmp_packets = statistics.get(
        "icmp",
        0
    )

    other_packets = statistics.get(
        "other",
        0
    )


    # Prevent division by zero
    safe_total = max(
        total_packets,
        1
    )


    # ---------------------------------------------------
    # Protocol Ratios
    # ---------------------------------------------------

    tcp_ratio = (
        tcp_packets
        / safe_total
    )

    udp_ratio = (
        udp_packets
        / safe_total
    )

    icmp_ratio = (
        icmp_packets
        / safe_total
    )


    # ---------------------------------------------------
    # Sets for Unique Values
    # ---------------------------------------------------

    source_ips = set()

    destination_ips = set()

    destination_ports = set()

    packet_lengths = []


    # ---------------------------------------------------
    # Read Packet Details
    # ---------------------------------------------------

    for packet in packet_details:

        source_ip = packet.get(
            "source_ip",
            "-"
        )

        destination_ip = packet.get(
            "destination_ip",
            "-"
        )

        destination_port = packet.get(
            "destination_port",
            "-"
        )

        packet_length = packet.get(
            "length",
            0
        )


        # Source IP
        if source_ip != "-":

            source_ips.add(
                source_ip
            )


        # Destination IP
        if destination_ip != "-":

            destination_ips.add(
                destination_ip
            )


        # Destination Port
        if destination_port != "-":

            try:

                destination_ports.add(
                    int(
                        destination_port
                    )
                )

            except (
                ValueError,
                TypeError
            ):

                pass


        # Packet Length
        try:

            packet_lengths.append(
                int(
                    packet_length
                )
            )

        except (
            ValueError,
            TypeError
        ):

            pass


    # ---------------------------------------------------
    # Packet Size Statistics
    # ---------------------------------------------------

    if packet_lengths:

        average_packet_size = (
            sum(packet_lengths)
            / len(packet_lengths)
        )

        maximum_packet_size = max(
            packet_lengths
        )

    else:

        average_packet_size = 0

        maximum_packet_size = 0


    # ---------------------------------------------------
    # AI Feature Dictionary
    # ---------------------------------------------------

    features = {

        "total_packets":
            total_packets,

        "tcp_packets":
            tcp_packets,

        "udp_packets":
            udp_packets,

        "icmp_packets":
            icmp_packets,

        "other_packets":
            other_packets,

        "tcp_ratio":
            tcp_ratio,

        "udp_ratio":
            udp_ratio,

        "icmp_ratio":
            icmp_ratio,

        "unique_source_ips":
            len(
                source_ips
            ),

        "unique_destination_ips":
            len(
                destination_ips
            ),

        "unique_destination_ports":
            len(
                destination_ports
            ),

        "average_packet_size":
            average_packet_size,

        "maximum_packet_size":
            maximum_packet_size
    }


    return features