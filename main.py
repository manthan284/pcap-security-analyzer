from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS
from collections import Counter

def analyze_pcap(filename):
    packets = rdpcap(filename)


    # Display the total number of packets
    print("Total packets: ", len(packets))

    protocol_counts = Counter()

    #Examine each packet
    for packet in packets:


        #-----------------------------
        # 1: Count protocol layers
        #------------------------------
        if ARP in packet: 
            protocol_counts["ARP"] +=1
    
        if IP in packet: 
            protocol_counts["IP"] +=1
    
        if IPv6 in packet: 
            protocol_counts["IPv6"] +=1
    
        if TCP in packet: 
            protocol_counts["TCP"] +=1
    
        if UDP in packet: 
            protocol_counts["UDP"] +=1
    
        if ICMP in packet: 
            protocol_counts["ICMP"] +=1
    
        if DNS in packet: 
            protocol_counts["DNS"] +=1
    
    print("\nProtocol Counts: ")
    
    for protocol, count in protocol_counts.most_common():
        print(f"{protocol}: {count}")


    #--------------------------------
    # 2: Count source and destination IPs
    #--------------------------------

    source_ips = Counter()
    destination_ips = Counter()

    for packet in packets:

        if IP in packet:
            source_ips[packet[IP].src] += 1
            destination_ips[packet[IP].dst] += 1

    print("\n Top 5 Source IP Addresses: ")
    for ip, count in source_ips.most_common(5):
        print(f"{ip}: {count} packets sent")

    print("\n Top 5 Destination IP Addresses: ")
    for ip, count in destination_ips.most_common(5):
        print(f"{ip}: {count} packets sent")


    #-------------------------------
    # 3: Count TCP and UDP ports
    #-------------------------------

    tcp_source_ports = Counter()
    tcp_destination_ports = Counter()
    udp_source_ports = Counter()
    udp_destination_ports = Counter()

    for packet in packets:

        if TCP in packet:
            tcp_source_ports[packet[TCP].sport] += 1
            tcp_destination_ports[packet[TCP].dport] += 1

        if UDP in packet:
            udp_source_ports[packet[UDP].sport] += 1
            udp_destination_ports[packet[UDP].dport] += 1

    print("\nTop 5 TCP Source Ports:")
    for port, count in tcp_source_ports.most_common(5):
        print(f"{port}: {count} packets")

    print("\nTop 5 TCP Destination Ports:")
    for port, count in tcp_destination_ports.most_common(5):
        print(f"{port}: {count} packets")
        
    print("\nTop 5 UDP Source Ports:")
    for port, count in udp_source_ports.most_common(5):
        print(f"{port}: {count} packets")

    print("\nTop 5 UDP Destination Ports:")
    for port, count in udp_destination_ports.most_common(5):
        print(f"{port}: {count} packets")


    #-------------------------------------
    # 4: Analyze network conversations
    #-------------------------------------

    conversations = Counter()

    for packet in packets:

        if TCP in packet:
            protocol = "TCP"
            source_ip = packet[IP].src if IP in packet else packet[IPv6].src
            destination_ip = packet[IP].dst if IP in packet else packet[IPv6].dst

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            source_ip = packet[IP].src if IP in packet else packet[IPv6].src
            destination_ip = packet[IP].dst if IP in packet else packet[IPv6].dst
            
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        else:
            continue

        conversation = (protocol, source_ip, source_port, destination_ip, destination_port)

        conversations[conversation] += 1

    print("\n Top 10 Network Conversations: ")

    for conversation, count in conversations.most_common(10):
        protocol, source_ip, source_port, destination_ip, destination_port = conversation

        print(f"{protocol} | "              
                f"{source_ip}:{source_port} -> "
                f"{destination_ip}:{destination_port} |"
                f"{count} packets")


    #--------------------------
    # 5: Analyze DNS queries
    #--------------------------

    dns_queries = Counter()

    for packet in packets:

        if DNS in packet:

            dns_layer = packet[DNS]

            if dns_layer.qd is not None:

                try:
                    query = dns_layer.qd.qname

                    if query:
                        query = query.decode("utf-8").rstrip(".")
                        dns_queries[query] += 1

                except (IndexError, AttributeError):
                    continue

    print("\nTop 10 DNS queries: ")

    for domain, count in dns_queries.most_common(20):
        print(f"{domain}: {count} queries")


    #--------------------------
    # 6: Analyze TCP Flags
    #--------------------------

    tcp_flags = Counter()

    for packet in packets:

        if TCP in packet:

            flags = packet[TCP].flags

            if flags.S:
                tcp_flags["SYN"] +=1

            if flags.A:
                tcp_flags["ACK"] +=1

            if flags.F:
                tcp_flags["FIN"] +=1

            if flags.R:
                tcp_flags["RST"] +=1

            if flags.P:
                tcp_flags["PSH"] +=1

            if flags.U:
                tcp_flags["URG"] +=1

    print("\nTCP Flags Counts: ")

    for flag, count in tcp_flags.most_common():
        print(f"{flag}: {count}")


    #----------------------------------
    # 7: Detect possible port scan
    #----------------------------------

    scan_attempts = {}

    for packet in packets:

        if TCP in packet and IP in packet:

            # check for SYN packets without ACK
            if packet[TCP].flags.S and not packet[TCP].flags.A:

                source_ip = packet[IP].src
                destination_ip = packet[IP].dst
                destination_port = packet[TCP].dport

                key = (source_ip, destination_ip)

                if key not in scan_attempts:

                    scan_attempts[key] = set()

                scan_attempts[key].add(destination_port)

    print("\nPossible Port Scan Detection: ")

    found_scan = False

    for(source_ip, destination_ip), ports in scan_attempts.items():

        if len(ports) >= 10:

            print(f"Poosible Port Scan: "
                f"{source_ip} -> {destination_ip} |"
                f"{len(ports)} different ports")

            found_scan = True

        if not found_scan:
            print("No possible port scans detected. ")


    #-------------------------------
    # 8: Detect unusual DNS activity
    #-------------------------------

    print("\nUnusual DNS Activity: ")

    found_dns_anomaly = False

    for domain, count in dns_queries.items():

        if count >= 10:

            print(f"Frequent DNS queries: "
                f"{domain} | {count}")

            found_dns_anomaly = True

    if not found_dns_anomaly:
        print("No unusual DNS activity detected. ")



    #------------------------------
    # 9: Detect repeated TCP resets
    #------------------------------

    tcp_resets = Counter()

    for packet in packets:

        if TCP in packet and IP in packet:

            if packet[TCP].flags.R:

                source_ip = packet[IP].src
                destination_ip = packet[IP].dst

                key = (source_ip, destination_ip)

                tcp_resets[key] += 1

    print("\n Repeated TCP Resets Activity: ")

    found_resets = False

    for(source_ip, destination_ip), count in tcp_resets.most_common():

        if count >= 10:

            print(f"Repeated TCP resets: "
                f"{source_ip} -> {destination_ip} | "
                f"{count} reset packets")

            found_resets = True

    if not found_resets:
        print("No repeated TCP reset activity detected. ")


    #---------------------------------
    # 10: Cleartext Protocol Detection
    #---------------------------------

    print("\nCleartext Protocol Detection")

    cleartext_ports = {
        21: "FTP",
        23: "Telnet",
        80: "HTTP"
    }

    cleartext_traffic = []

    found_cleartext = False

    for packet in packets:

        if TCP in packet:

            source_ip = packet[IP].src if IP in packet else None
            destination_ip = packet[IP].dst if IP in packet else None

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

            if destination_port in cleartext_ports:

                protocol = cleartext_ports[destination_port]

                cleartext_traffic.append({
                    "protocol": protocol,
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "source_port": source_port,
                    "destination_port": destination_port
                })

                print(
                    f"Cleartext protocol detected: "
                    f"{protocol} | "
                    f"{source_ip}:{source_port} -> "
                    f"{destination_ip}:{destination_port}"
                )

                found_cleartext = True

    if not found_cleartext:
        print("No cleartext protocols detected.")


    #-----------------------------
    # 11: High Risk Port Detection
    #-----------------------------

    print("\nHigh Risk Port Detection:")

    high_risk_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        445: "SMB",
        3389: "RDP",
        5900: "VNC"
    }

    high_risk_traffic = []

    found_high_risk = False

    for packet in packets:

        if TCP in packet and IP in packet:

            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

            if destination_port in high_risk_ports:

                protocol = high_risk_ports[destination_port]

                high_risk_traffic.append({
                    "protocol": protocol,
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "source_port": source_port,
                    "destination_port": destination_port
                })

                print(
                    f"Security-sensitive traffic: "
                    f"{protocol} | "
                    f"{source_ip}:{source_port} -> "
                    f"{destination_ip}:{destination_port}"
                )

                found_high_risk = True

    if not found_high_risk:
        print("No high-risk ports detected.")


    #--------------------------------
    # 12: Improved SYN Scan Detection
    #--------------------------------

    print("\nImproved SYN Scan Detection: ")

    syn_attempts = {}

    for packet in packets:

        if TCP in packet and IP in packet:

            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

            # SYN packet without ACK
            if packet[TCP].flags.S and not packet[TCP].flags.A:

                key = (
                    source_ip,
                    destination_ip,
                    source_port,
                    destination_port
                )

                syn_attempts[key] = False

            # SYN-ACK response
            elif packet[TCP].flags.S and packet[TCP].flags.A:

                response_key = (
                    destination_ip,
                    source_ip,
                    destination_port,
                    source_port
                )

                if response_key in syn_attempts:
                    syn_attempts[response_key] = True

    # Count unsuccessful SYN attempts
    syn_scan_results = {}

    for key, received_response in syn_attempts.items():

        if not received_response:

            source_ip = key[0]
            destination_ip = key[1]
            destination_port = key[3]

            pair = (source_ip, destination_ip)

            if pair not in syn_scan_results:
                syn_scan_results[pair] = set()

            syn_scan_results[pair].add(destination_port)


    found_syn_scan = False

    for (source_ip, destination_ip), ports in syn_scan_results.items():

        if len(ports) >= 10:

            print(
                f"Possible SYN Scan: "
                f"{source_ip} -> {destination_ip} | "
                f"{len(ports)} unanswered ports"
            )

            found_syn_scan = True

    if not found_syn_scan:
        print("No possible SYN scans detected.")



    return {
    "total_packets": len(packets),
    "protocol_counts": protocol_counts,
    "source_ips": source_ips,
    "destination_ips": destination_ips,
    "tcp_source_ports": tcp_source_ports,
    "tcp_destination_ports": tcp_destination_ports,
    "udp_source_ports": udp_source_ports,
    "udp_destination_ports": udp_destination_ports,
    "conversations": conversations,
    "dns_queries": dns_queries,
    "tcp_flags": tcp_flags,
    "scan_attempts": scan_attempts,
    "tcp_resets": tcp_resets,
    "cleartext_traffic": cleartext_traffic,
    "high_risk_traffic": high_risk_traffic,
    "syn_scan_results": syn_scan_results
    }





if __name__ == "__main__":
    results = analyze_pcap()




















