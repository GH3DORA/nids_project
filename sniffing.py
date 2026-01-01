from scapy.all import sniff
from analysis import analyze_packet
from logger import log_packet

def process_packet(packet):
    log_packet(packet)
    analyze_packet(packet)
def start_sniffing():
    sniff(prn=process_packet,store=False)



# from scapy.all import sniff,IP,TCP,UDP,ICMP
# from datetime import datetime
# import csv
# output_file="traffic_log.csv"

# with open(output_file,"w",newline="") as f:
#     writer=csv.writer(f)
#     writer.writerow([
#         "timestamp",
#         "src_ip",
#         "dst_ip",
#         "src_port",
#         "dst_port",
#         "protocol",
#         "packet_lengh",
#         "tcp_flags",
#         "ttl"
#     ])

# def process_packet(packet):
#     if IP in packet:
#         timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#         src_ip=packet[IP].src
#         dst_ip=packet[IP].dst
#         packet_length=len(packet)
#         ttl=packet[IP].ttl
#         src_port=None
#         dst_port=None
#         tcp_flags=None

#         if TCP in packet:
#             src_port=packet[TCP].sport
#             dst_port=packet[TCP].dport
#             tcp_flags=packet[TCP].flags
#             protocol_name="TCP"
#         elif UDP in packet:
#             src_port=packet[UDP].sport
#             dst_port=packet[UDP].dport
#             protocol_name="UDP"
#         elif ICMP in packet:
#             protocol_name="ICMP"
#         else:
#             protocol_name="OTHER"

#         with open(output_file,"a",newline="") as f:
#             writer=csv.writer(f)
#             writer.writerow([
#                 timestamp,
#                 src_ip,
#                 dst_ip,
#                 src_port,
#                 dst_port,
#                 protocol_name,
#                 packet_length,
#                 tcp_flags,
#                 ttl
#             ])
#         print(f"+ {protocol_name} {src_ip} -> {dst_ip}")