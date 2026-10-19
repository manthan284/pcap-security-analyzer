# PCAP Security Analyzer

A Python-based network traffic analysis tool that examines PCAP and PCAPNG files to identify protocol activity, network conversations, and potential security indicators through an interactive Streamlit dashboard.

## Features

- **Protocol Analysis:** Summarizes packet counts by protocol.
- **IP Analysis:** Identifies top source and destination IP addresses.
- **Port Analysis:** Examines TCP and UDP port activity.
- **DNS Analysis:** Extracts DNS queries and supports domain searching.
- **TCP Flag Analysis:** Visualizes TCP flag activity.
- **Network Conversations:** Reviews communication between network endpoints.
- **Security Detection:** Flags cleartext traffic, high-risk port activity, possible SYN scans, and repeated TCP resets.
- **Severity Labels:** Assigns preliminary rule-based severity levels to findings.
- **CSV Export:** Downloads detected security findings for further analysis.

## Technology Stack

- Python
- Scapy
- Streamlit
- Pandas

## Getting Started

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd pcap-analyzer
```

### 2. Create and activate a virtual environment

```bash
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install scapy streamlit pandas
```

### 4. Run the application

```bash
streamlit run app.py
```

Open the local URL displayed in the terminal.

## Usage

1. Launch the application.
2. Upload a `.pcap` or `.pcapng` capture file.
3. Explore protocol, IP, port, DNS, TCP flag, and conversation analysis.
4. Review the security indicators.
5. Download the findings as a CSV file.

## Detection Notes

The analyzer uses rule-based heuristics. High-risk port activity, possible SYN scans, and repeated TCP resets are indicators that may warrant investigation; they do not independently establish malicious activity.

## Future Improvements

- Add AI-assisted analysis of detected security indicators.
- Improve detection accuracy and reduce duplicate findings.
- Expand IPv6 support and add automated testing.
- Improve reporting and documentation.

## Disclaimer

Use this tool only on network captures you own or are authorized to analyze. Handle packet captures carefully because they may contain sensitive information.
