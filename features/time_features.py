import time
from collections import defaultdict, deque

TIME_WINDOW=10 #sliding window

packet_times=defaultdict(deque)
packet_sizes=defaultdict(deque)
dst_ports=defaultdict(deque)
syn_packets=defaultdict(deque)
icmp_packets=defaultdict(deque)

def cleanup(src_ip,current_time):
    def clean(queue):
        while queue and current_time-queue[0][0]>TIME_WINDOW:
            queue.popleft()
    
    clean(packet_times[src_ip])
    clean(packet_sizes[src_ip])
    clean(dst_ports[src_ip])
    clean(syn_packets[src_ip])
    clean(icmp_packets[src_ip])

def update_time_features(packet):
    if not packet.haslayer("IP"):
        return
    current_time=time.time()
    src_ip=packet["IP"].src

    packet_times[src_ip].append(current_time)
    packet_sizes[src_ip].append(current_time,len(packet))
    if packet.haslayer("TCP"):
        dst_ports[src_ip].append(current_time,packet["TCP"].dport)
        if packet["TCP"].flags == "S":
            syn_packets[src_ip].append(current_time)
    if packet.haslayer("ICMP"): 
        icmp_packets[src_ip].append(current_time)
    cleanup(src_ip,current_time)

def extract_time_features(packet):
    if not packet.haslayer("IP"):
        return
    
    src_ip=packet["IP"].src
    packet_rate=len(packet_times[src_ip])/TIME_WINDOW
    average_packet_size=sum(packet_sizes[src_ip])/len(packet_times[src_ip]) if len(packet_times[src_ip])>0 else 0
    unique_ports=len(set(dst_ports[src_ip]))
    syn_rate=len(syn_packets[src_ip])/TIME_WINDOW
    icmp_rate=len(icmp_packets[src_ip])/TIME_WINDOW

    return [
        packet_rate,
        average_packet_size,
        unique_ports,
        syn_rate,
        icmp_rate
    ]