# Network Traffic Analyzer Dashboard

## Overview

The **Network Traffic Analyzer Dashboard** is a web-based application that captures and analyzes network packet data in real-time. This application utilizes Scapy for packet capturing and Dash for creating interactive visualizations. It provides insights into network traffic, detects potential Distributed Denial of Service (DDoS) attacks, and identifies anomalies based on protocol and source IP addresses.

## Features

1. **Real-time Packet Capture**: The application captures network packets in real-time for a specified duration, analyzing the traffic for different protocols (TCP, UDP, ICMP, and others).

2. **DDoS Attack Detection**: It monitors the packet count for each protocol and identifies potential DDoS attacks based on predefined thresholds.

3. **Anomaly Detection**: The application detects anomalies based on the request count from individual source IP addresses for each protocol.

4. **Interactive Graphs**: The dashboard provides interactive graphs to visualize the captured data, DDoS attack detections, anomalies, and request counts by source IP.

## Graphs Explained

1. **Traffic Count for Selected Protocols Over Time**:
   - This graph shows the count of packets for the selected protocols over time intervals (5 seconds each).
   - Users can select multiple protocols to visualize their traffic patterns, aiding in monitoring and analysis.

2. **Detected DDoS Attacks**:
   - This bar chart displays instances of detected DDoS attacks, indicating the protocol involved, the starting interval of the attack, and the packet counts during that period.
   - It helps identify which protocols are most vulnerable to DDoS attacks and when these attacks occur.

3. **Detected Anomalies with Source IP**:
   - This graph shows anomalies based on the count of requests from each source IP for different protocols.
   - It highlights any IP addresses that exhibit unusual traffic behavior, which may indicate malicious activity.

4. **Protocol Request Count by Source IP**:
   - This bar chart visualizes the number of requests made by each source IP address for each protocol.
   - It provides insight into the distribution of traffic and helps identify any suspicious source IPs that may be flooding the network with requests.

## Installation

To set up the application, you need to install the required libraries. Follow these steps:

1. **Clone the repository**:
   ```bash
   git clone <link add kardo>
   cd network-traffic-analyzer

2. **Create a virtual environment** (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`

3. **Install the required dependencies**:
   ```bash
   pip install scapy dash pandas plotly

4. **Run the application**:
   ```bash
   python mini_project.py

5. **Access the dashboard**:
   Open your web browser and go to `http://127.0.0.1:8050` to access the dashboard.

