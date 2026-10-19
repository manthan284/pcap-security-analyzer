import streamlit as st
from main import analyze_pcap
import pandas as pd

st.title("PCAP Security analyzer")

uploaded_file = st.file_uploader(
    "Upload a PCAP file", 
    type = ["pcap", "pcapng"]
)

if uploaded_file is not None:


    st.subheader("Capture Information")

    st.write("**File Name**", uploaded_file.name)
    st.write("**File Size**",
             f"{uploaded_file.size/1024:.2f} KB")

    
    with open("uploaded_capture.pcap", "wb") as f:
        f.write(uploaded_file.getbuffer())

    results = analyze_pcap("uploaded_capture.pcap")

    if results["total_packets"]>0:
        st.success("PCAP analyzed successfully.")
    else: 
        st.warning("The uploaded capture contains no packets")



    st.subheader("Overview")

    col1, col2 = st.columns(2)

    with col1:
        st.metric(
            "Total Packets", 
            results["total_packets"]
        )

    with col2:
        st.metric(
            "Protocols Detected",
            len(results["protocol_counts"])
        )



    st.subheader("Protocol Analysis")

    st.bar_chart(results["protocol_counts"])



    st.subheader("IP Address Analysis")

    ip_search = st.text_input(
        "Search IP Addresses",
        placeholder = "Enter an IP Address..."
    )

    col1, col2 = st.columns(2)

    with col1:
        st.write("Top Source IPs")

        source_data = [
            {"IP Address": ip, "Packets" : count}
            for ip, count in results["source_ips"].most_common()
            if ip_search in ip
        ]

        st.dataframe(
            source_data[:10],
            use_container_width=True,
            hide_index=True
        )

    with col2:
        st.write("Top Destination IPs")

        destination_data = [
            {"IP Address": ip, "Packets": count}
            for ip, count in results["destination_ips"].most_common()
            if ip_search in ip
        ]

        st.dataframe(
            destination_data[:10],
            use_container_width=True,    
            hide_index=True      
        )

    if ip_search and not source_data and not destination_data:
        st.info("No matching IP addresses found.")





    st.subheader("Port analysis")

    port_search = st.text_input(
        "Search destination port",
        placeholder = "Enter a port number, e.g. 443..."
    )


    col1, col2 = st.columns(2)

    with col1:
        st.write("Top TCP Destination Ports")

        tcp_data = [
            {"Port": port, "Packets": count}
            for port, count in results["tcp_destination_ports"].most_common()
            if port_search in str(port) 
        ]

        st.dataframe(
            tcp_data[:10],
            use_container_width=True,
            hide_index=True
        )

    with col2:
        st.write("Top UDP Destination Ports")

        udp_data = [
            {"Port": port, "Packets": count}
            for port, count in results["udp_destination_ports"].most_common()
            if port_search in str(port) 
        ]

        st.dataframe(
            udp_data[:10],
            use_container_width=True,
            hide_index=True
        )

    if port_search and not tcp_data and not udp_data:
        st.info("No matching destination port found.")



    st.subheader("DNS Analysis")
    
    dns_queries = results["dns_queries"]

    search_domain = st.text_input(
        "Search DNS domains",
        placeholder="Enter a domain name.."
    )

    dns_data = []

    for domain, count in dns_queries.most_common():

        if search_domain.lower() in domain.lower():
            dns_data.append(
                { "Domain":domain,
                "Query Count":count}
            )

    st.dataframe(
        dns_data[:20],
        use_container_width=True
    )

    if not dns_data:
            st.info("No matching DNS queries found.")



    st.subheader("TCP Flag Analysis")

    selected_flags = st.multiselect(
        "Select TCP Flags",
        options = list(results["tcp_flags"].keys()),
        default = list(results["tcp_flags"].keys())
    )

    filtered_flags = {
        flag: count
        for flag, count in results["tcp_flags"].items()
        if flag in selected_flags
    }

    if filtered_flags:
        st.bar_chart(filtered_flags)
    else:
        st.info("Select at least one TCP flag to display the chart.")




    st.subheader("Network Conversations")

    conversation_data = []

    for conversation, count in results["conversations"].most_common(20):

        protocol, source_ip, source_port, destination_ip, destination_port = conversation

        conversation_data.append(
            {"Protocol" : protocol, 
            "Source" : f"{source_ip}:{source_port}",
            "Destination" : f"{destination_ip}:{destination_port}",
            "Packets" : count}
        )

    st.dataframe(
        conversation_data, 
        use_container_width=True
    )




    st.subheader("Security Findings")



    st.write("### Cleartext Findings")

    if results["cleartext_traffic"]:

        st.dataframe(
            results["cleartext_traffic"],
            use_container_width=True
        )
    else:
        st.success("No cleartext protocols detected.")


    
    st.write("### High Risk Port Findings")

    if results["high_risk_traffic"]:

        st.dataframe(
            results["high_risk_traffic"],
            use_container_width=True
        )
    else:
        st.success("No high-risk port traffic detected.")



    st.write("### Possible SYN Scans")

    syn_scan_findings = []

    for (source_ip, destination_ip), ports in results["syn_scan_results"].items():

        if len(ports) >= 10:
            syn_scan_findings.append({
                "Source IP": source_ip,
                "Destination IP": destination_ip,
                "Unanswered Ports": len(ports),
                "Ports": ",".join(str(port) for port in sorted(ports))
            })

    if syn_scan_findings:

        st.warning(f"Possible SYN Scans Detected: {len(syn_scan_findings)}")

        st.dataframe(
            syn_scan_findings,
            use_container_width=True
        )

    else:
        st.success("No possible SYN scans detected.")



    st.write("### Repeted TCP Reset Activity")

    tcp_reset_findings = []

    for (source_ip, destiniation_ip), count in results["tcp_resets"].most_common():

        if count >= 10:
            tcp_reset_findings.append({
                "Source IP": source_ip,
                "Destination IP": destination_ip,
                "RST Packets": count
            })

    if tcp_reset_findings:

        st.dataframe(
            tcp_reset_findings,
            use_container_width = True
        )

    else:
        st.success("No TCP Reset Activity Detected. ")



    st.subheader("Security Findings")

    st.write("### Findings Summary")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Cleartext Events", 
            len(results["cleartext_traffic"])
        )

    with col2:
        st.metric(
            "High-Risk Port Events",
            len(results["high_risk_traffic"]
            )
        )

    with col3:
        st.metric(
            "Possible SYN Scans",
            len(syn_scan_findings)
        )

    with col4:
        st.metric(
            "TCP Reset Pairs",
            len("tcp_reset_findings")
        )





    st.subheader("Network Conversations")

    selected_protocol = st.selectbox(
        "Filter by Protocol",
        ["All", "TCP", "UDP"]

    )

    conversation_data = []

    for conversation, count in results["conversations"].most_common():

        protocol, source_ip, source_port, destination_ip, destination_port = conversation

        if selected_protocol != "All" and protocol != selected_protocol:
            continue


        conversation_data.append({
            "Protocol": protocol,
            "Source" : f"{source_ip}:{source_port}",
            "Destination": f"{destination_ip}:{destination_port}",
            "Packets":count 
        })

    st.dataframe(
        conversation_data[:20],
        use_container_width=True
    )




    st.subheader("Export Security Findings")

    all_findings = []

    for item in results["cleartext_traffic"]:
        all_findings.append({
            "Severity": "High",
            "Findings Type": "Cleartext Traffic",
            **item
        })

    for item in results["high_risk_traffic"]:
        all_findings.append({
            "Severity": "Medium",
            "Finding Type": "High-Risk Port Traffic",
            **item
        })

    for (source_ip, destination_ip), ports in results["syn_scan_results"].items():
        if len(ports)>=10:
            all_findings.append({
                "Severity": "High",
                "Findings Type": "Possible SYN Scan",
                "Source IP": source_ip,
                "Destination IP": destination_ip,
                "Unanswered Ports": len(ports),
                "Ports": ",".join(str(port) for port in sorted(ports))
            })

    for (source_ip, destination_ip), count in results["tcp_resets"].most_common():
        if count >= 10:
            all_findings.append({
                "Severity": "Low",
                "Findings Type": "Repeated TCP Resets",
                "Source IP": source_ip,
                "Destination IP": destination_ip,
                "RST Packets": count
            })   

    findings_df = pd.DataFrame(all_findings)

    st.download_button(
        label = "Download Security Findings (CSV)",
        data = findings_df.to_csv(index=False).encode("utf-8"),
        file_name = "security_findings.csv",
        mime = "text/csv",
        disabled = findings_df.empty
    )

    if findings_df.empty:
        st.info("No findings met the current detection rule.")

        

