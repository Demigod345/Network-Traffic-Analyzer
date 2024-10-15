from scapy.all import sniff, IP
from collections import defaultdict
import pandas as pd
import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.express as px
import time

# Protocol names mapping
protocol_names = {1: "ICMP", 6: "TCP", 17: "UDP"}

# Global variables for protocol-specific analysis
protocol_count_vectors = {"TCP": [], "UDP": [], "ICMP": [], "Other": []}
source_count_vector = defaultdict(int)
protocol_source_count = defaultdict(lambda: {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0})
interval_duration = 5  # Capture interval duration in seconds
total_capture_time = 20  # Total capture time of 2 minutes (120 seconds)
traffic_data = []
dos_threshold = 10  # Set a threshold for DoS attack detection
dos_attacks = []
anomaly_thresholds = {"TCP": 50, "UDP": 30, "ICMP": 20, "Other": 10}  # Thresholds for protocol-specific anomaly detection
anomalies = []

# Function to capture and analyze packet data
def packet_summary(packet):
    if packet.haslayer(IP):
        protocol = packet[IP].proto
        protocol_name = protocol_names.get(protocol, "Other")
        traffic_data.append({
            "Source_IP": packet[IP].src,
            "Destination_IP": packet[IP].dst,
            "Protocol": protocol_name,
            "Timestamp": time.time()  # Add timestamp for tracking packets over time
        })

# Function to detect potential DoS attacks based on traffic volume in a time window
def detect_ddos_attacks():
    for protocol in protocol_count_vectors:
        # Check for 5 consecutive intervals exceeding the threshold
        for i in range(len(protocol_count_vectors[protocol]) - 4):
            if all(count > dos_threshold for count in protocol_count_vectors[protocol][i:i + 5]):
                dos_attacks.append((protocol, i, protocol_count_vectors[protocol][i:i + 5]))

# New function to detect anomalies based on source IP and protocol request counts
def detect_protocol_source_anomalies():
    for source_ip, counts in protocol_source_count.items():
        for protocol, count in counts.items():
            if count > anomaly_thresholds[protocol]:  # Compare count with the threshold for the protocol
                anomalies.append({
                    "Source_IP": source_ip,
                    "Protocol": protocol,
                    "Count": count
                })

# Packet capture and analysis per interval
def capture_packets(interface="eth0", duration=total_capture_time):
    start_time = time.time()
    while time.time() - start_time < duration:
        # Initialize count dictionary for this interval
        interval_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

        # Capture packets for the interval duration
        sniff(iface=interface, timeout=interval_duration, prn=packet_summary)

        # Analyze captured packets and count by protocol
        for packet in traffic_data:
            protocol = packet["Protocol"]
            source_ip = packet["Source_IP"]
            interval_count[protocol] += 1
            source_count_vector[source_ip] += 1
            protocol_source_count[source_ip][protocol] += 1  # Update count of requests for each protocol from this source IP

        # Store the count of each protocol for the interval
        protocol_count_vectors["TCP"].append(interval_count["TCP"])
        protocol_count_vectors["UDP"].append(interval_count["UDP"])
        protocol_count_vectors["ICMP"].append(interval_count["ICMP"])
        protocol_count_vectors["Other"].append(interval_count["Other"])

        # Clear traffic data for the next interval
        traffic_data.clear()

# Uncomment the following line to enable live packet capturing
# capture_packets()

# Create Dash app for visualization
app = dash.Dash(__name__)

# Layout for the dashboard
app.layout = html.Div([
    html.H1("Network Traffic Analyzer Dashboard", style={'textAlign': 'center'}),

    html.Label("Select Protocol(s):"),
    dcc.Dropdown(
        id='protocol-dropdown',
        options=[
            {'label': 'TCP', 'value': 'TCP'},
            {'label': 'UDP', 'value': 'UDP'},
            {'label': 'ICMP', 'value': 'ICMP'},
            {'label': 'Other', 'value': 'Other'}
        ],
        value=['TCP'],  # Default selected protocol
        multi=True,  # Enable multi-selection
        style={'width': '50%'}
    ),

    dcc.Graph(id='protocol-traffic-graph'),

    html.H2("Detected DDoS Attacks"),
    dcc.Graph(id='dos-attacks-graph'),

    html.H2("Detected DoS Attacks"),
    dcc.Graph(id='anomaly-graph'),

    html.H2("Protocol Request Count by Source IP"),
    dcc.Graph(id='protocol-source-graph')
])

# Callback to update graph based on selected protocol(s)
@app.callback(
    Output('protocol-traffic-graph', 'figure'),
    [Input('protocol-dropdown', 'value')]
)
def update_graph(selected_protocols):
    intervals = list(range(1, len(protocol_count_vectors['TCP']) + 1))  # Using 'TCP' length for interval count, assuming all have same length

    # Create a line chart for each selected protocol
    data = []
    for protocol in selected_protocols:
        data.append({
            'x': intervals,
            'y': protocol_count_vectors[protocol],
            'type': 'line',
            'name': protocol,
        })

    figure = {
        'data': data,
        'layout': {
            'title': 'Traffic Count for Selected Protocols Over Time',
            'xaxis': {'title': 'Intervals (5 seconds each)'},
            'yaxis': {'title': 'Packet Count'},
            'hovermode': 'closest'
        }
    }
    return figure

# Update DoS Attacks Graph
@app.callback(
    Output('dos-attacks-graph', 'figure'),
    Input('dos-attacks-graph', 'id')
)
def update_dos_attacks_graph(_):
    detect_ddos_attacks()  # Call the function to detect DoS attacks
    dos_df = pd.DataFrame(dos_attacks, columns=['Protocol', 'Start_Interval', 'Counts'])
    fig = px.bar(dos_df, x='Start_Interval', y='Counts', color='Protocol', title="Detected DDoS Attacks")
    return fig

# Update Anomaly Graph
@app.callback(
    Output('anomaly-graph', 'figure'),
    Input('anomaly-graph', 'id')
)
def update_anomaly_graph(_):
    detect_protocol_source_anomalies()  # Call the new function for protocol-specific source IP anomalies
    anomalies_df = pd.DataFrame(anomalies)
    fig = px.bar(anomalies_df, x='Source_IP', y='Count', color='Protocol', orientation='h', title="Detected Dos Attacks with Source IP")
    return fig

# New graph to show request count by source IP for each protocol
@app.callback(
    Output('protocol-source-graph', 'figure'),
    Input('protocol-source-graph', 'id')
)
def update_protocol_source_graph(_):
    protocol_source_df = pd.DataFrame([
        {"Source_IP": source_ip, "Protocol": protocol, "Count": count}
        for source_ip, counts in protocol_source_count.items()
        for protocol, count in counts.items()
    ])

    if not protocol_source_df.empty:
        fig = px.bar(protocol_source_df, x='Source_IP', y='Count', color='Protocol', title="Protocol Request Count by Source IP")
    else:
        fig = px.bar(title="No Data Available")

    return fig

# Run the app
if __name__ == '__main__':
    capture_packets()  # Capture packets for 2 minutes
    app.run_server(debug=True)