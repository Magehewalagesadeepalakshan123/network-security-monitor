from collections import defaultdict, Counter


def detect_suspicious_activity(packet_records):

    alerts = []

    ports_by_ip = defaultdict(set)
    packet_count = Counter()
    icmp_count = Counter()

    for packet in packet_records:

        source_ip = packet["source_ip"]
        protocol = packet["protocol"]
        destination_port = packet["destination_port"]

        if source_ip == "-":
            continue

        packet_count[source_ip] += 1

        # Track destination ports used by each source
        if destination_port != "-":
            ports_by_ip[source_ip].add(
                destination_port
            )

        # Count ICMP traffic
        if protocol == "ICMP":
            icmp_count[source_ip] += 1


    # Rule 1 - Many destination ports
    for source_ip, ports in ports_by_ip.items():

        if len(ports) >= 20:

            alerts.append({
                "alert_type": "Possible Scan Activity",
                "severity": "HIGH",
                "source_ip": source_ip,
                "description":
                    f"{source_ip} contacted "
                    f"{len(ports)} different destination ports."
            })


    # Rule 2 - High packet volume
    for source_ip, count in packet_count.items():

        if count >= 1000:

            alerts.append({
                "alert_type": "High Packet Activity",
                "severity": "MEDIUM",
                "source_ip": source_ip,
                "description":
                    f"{source_ip} generated "
                    f"{count} packets."
            })


    # Rule 3 - High ICMP activity
    for source_ip, count in icmp_count.items():

        if count >= 100:

            alerts.append({
                "alert_type": "High ICMP Activity",
                "severity": "MEDIUM",
                "source_ip": source_ip,
                "description":
                    f"{source_ip} generated "
                    f"{count} ICMP packets."
            })


    return alerts