import time
from scapy.utils import PcapWriter
from scapy.packet import Packet

severity={
    "PORT_SCAN":"MEDIUM",
    "DoS":"HIGH",
    "DDoS":"HIGH",
    "BRUTE_FORCE":"LOW",
    "ANOMALY":"MEDIUM"
}

attack_stats={
    "PORT_SCAN":0,
    "DoS":0,
    "DDoS":0,
    "BRUTE_FORCE":0,
    "ANOMALY":0
}

ALERT_LOG_FILE="traffic_log.csv"
PCAP_FILE="captured_traffic.pcap"

def log_alert(alert_type,src_ip,dst_ip,protocol,extra_info=""):

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    attack_stats.setdefault(alert_type,0)
    attack_stats[alert_type]+=1

    log_entry=(
        f"{timestamp}",
        f"{alert_type}",
        f"{severity[alert_type]}",
        f"{src_ip},{dst_ip}",
        f"{protocol}",
        f"{extra_info}\n"
    )
    with open(ALERT_LOG_FILE,"a") as f:
        f.write(",".join(log_entry) + "\n")

pcap_writer=PcapWriter(PCAP_FILE,append=True,sync=True)
def log_packet(packet:Packet):
    pcap_writer.write(packet)

def printstats():
    print("========== ATTACK SUMMARIES ==========")
    for attack,count in attack_stats.items():
        print(f"{attack} : {count}")