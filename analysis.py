from collections import defaultdict
import time
from rules import PORT_SCAN_THRESHOLD, PORT_SCAN_TIME_WINDOW, SYN_FLOOD_THRESHOLD, SYN_FLOOD_WINDOW_TIME, ICMP_THRESHOLD, ICMP_TIME_WINDOW, BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_SENSITIVE_PORTS, BRUTE_FORCE_TIME_WINDOW
from logger import log_alert
from ml_detector import analyze_packet_ml
from features.flow_features import update_flow, extract_flow_features
from features.time_features import update_time_features, extract_time_features

port_activity=defaultdict(list)
syn_activity=defaultdict(list)
icmp_activity=defaultdict(list)
login_attempts=defaultdict(list)

def analyze_packet(packet):

    if not packet.haslayer("IP"):
        return
    
    src_ip=packet["IP"].src
    dst_ip=packet["IP"].dst
    protocol=packet["IP"].proto

    print(f"Analysing packet from {src_ip} -> {dst_ip}...")

    # ========================= CHECKING PORT SCAN =========================
    if packet.haslayer("TCP"):
        dst_port=packet["TCP"].dport
        current_time=time.time()
        port_activity[src_ip].append((dst_port,current_time))
        # removing old entries
        port_activity[src_ip]=[
            (p,t) for p,t in port_activity[src_ip] #creating a new list by looping over the old list
            if current_time-t<=PORT_SCAN_TIME_WINDOW #rebuilding the list, not modifying in-place
        ]
        unique_ports=set()
        for p,_ in port_activity[src_ip]:
            unique_ports.add(p)
        if len(unique_ports)>=PORT_SCAN_THRESHOLD:
            log_alert(
                "PORT_SCAN",
                src_ip,
                dst_ip,
                protocol,
                f"Ports - {list(unique_ports)}, Count - {len(unique_ports)}"
            )

    # ========================= CHECKING SYN FLOODING (DoS) =========================
    if packet.haslayer("TCP"):
        current_time=time.time()
        if packet["TCP"].flags & 0x02:

            src_ip=packet["IP"].src
            current_time=time.time()

            syn_activity[src_ip].append(current_time)
            syn_activity[src_ip]=[
                ct for ct in syn_activity[src_ip] if current_time-ct<=SYN_FLOOD_WINDOW_TIME
            ]
            if len(syn_activity[src_ip])>=SYN_FLOOD_THRESHOLD:
                log_alert(
                "DoS",
                src_ip,
                dst_ip,
                protocol,
                f"SYN packets recieved - {len(syn_activity[src_ip])}"
            )

    # ========================= CHECKING ICMP FLOODING (DDoS) =========================
    if packet.haslayer("ICMP"):
        current_time=time.time()

        icmp_activity[src_ip].append(current_time)

        icmp_activity[src_ip]=[
            ct for ct in icmp_activity[src_ip] if current_time-ct<=ICMP_TIME_WINDOW
        ] 
        if len(icmp_activity[src_ip])>=ICMP_THRESHOLD:
            log_alert(
                "DDoS",
                src_ip,
                dst_ip,
                protocol,
                f"ICMP packets recieved - {len(icmp_activity[src_ip])}"
            )

    # ========================= BRUTE FORCE LOGIN DETECTION =========================
    if packet.haslayer("TCP"):
        dst_port=packet["TCP"].dport
        if dst_port in BRUTE_FORCE_SENSITIVE_PORTS:
            src_ip=packet["IP"].src
            current_time=time.time()

            login_attempts[src_ip].append(current_time)

            login_attempts[src_ip]=[
                ct for ct in login_attempts[src_ip] if current_time-ct<=BRUTE_FORCE_TIME_WINDOW
            ]

            if len(login_attempts[src_ip])>=BRUTE_FORCE_THRESHOLD:
                log_alert(
                    "BRUTE_FORCE",
                    src_ip,
                    dst_ip,
                    protocol,
                    f"Login attempts - {len(login_attempts[src_ip])}"
                )

    # ========================= ML MODEL =========================

    def get_traffic_class(packet):
        if packet.haslayer("ICMP"):
            return "ICMP"
        if packet.haslayer("TCP"):
            if packet["TCP"].dport in [80,443]:
                return "WEB"
            if packet["TCP"].dport in [21,22,23]:
                return "LOGIN"
            return "TCP_OTHER"
        if packet.haslayer("UDP"):
            return "UDP"
        return "OTHER"
    traffic_class=get_traffic_class(packet)
    update_flow(packet)
    update_time_features(packet)
    time_features=extract_time_features(packet)
    flow_features=extract_flow_features(packet)
    if time_features is None or flow_features is None:
        return
    combined_features=time_features+flow_features
    # OLD -> ml_result=analyze_packet_ml(packet). Improve  detection by checking with flow and time features.
    ml_result=analyze_packet_ml(combined_features,traffic_class)
    if ml_result is not None:
        log_alert(
            "ANOMALY",
            src_ip,
            dst_ip,
            protocol,
            f"Traffic Class = {traffic_class}, Anomaly score = {ml_result}"
        )










# from scapy.all import IP,TCP,UDP

# packet_counts={}
# def analyze_packet(packet):
#     if IP in packet:
#         src=packet[IP].src
#         dst=packet[IP].dst
#         proto=packet[IP].proto
#         length=len(packet)
#         packet_counts[src]=packet_counts.get(src,0)+1

#         print(f"[IP] {src} -> {dst}, [Protocol] {proto}, [Length] {length}, [Packet Count] {packet_counts[src]}  ")

#         if TCP in packet:
#             tcp_flags=packet[TCP].flags
#             print(f"[Sport] {packet[TCP].sport}, [Dport] {packet[TCP].dport}, [Flags] {tcp_flags}")
#         elif UDP in packet:
#             print(f"[Sport] {packet[UDP].sport}, [Dport] {packet[UDP].dport}")