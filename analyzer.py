from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP


def analyze_capture(file_path):

    packets = rdpcap(file_path)

    statistics = {
        "total": len(packets),
        "tcp": 0,
        "udp": 0,
        "icmp": 0,
        "other": 0
    }

    packet_details = []

    for number, packet in enumerate(packets, start=1):

        source_ip = "-"
        destination_ip = "-"

        source_port = "-"
        destination_port = "-"

        protocol = "OTHER"

        packet_length = len(packet)

        # IPv4
        if IP in packet:

            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

        # IPv6
        elif IPv6 in packet:

            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst


        # TCP
        if TCP in packet:

            protocol = "TCP"

            statistics["tcp"] += 1

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport


        # UDP
        elif UDP in packet:

            protocol = "UDP"

            statistics["udp"] += 1

            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport


        # ICMP
        elif ICMP in packet:

            protocol = "ICMP"

            statistics["icmp"] += 1


        # Other
        else:

            statistics["other"] += 1


        packet_details.append({

            "number": number,

            "source_ip": source_ip,

            "destination_ip": destination_ip,

            "protocol": protocol,

            "source_port": source_port,

            "destination_port": destination_port,

            "length": packet_length

        })


    return statistics, packet_details