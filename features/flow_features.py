import time
from collections import defaultdict

FLOW_TIMEOUT=30

flows=defaultdict(lambda:{
    "start_time":0,
    "last_seen":0,
    "packet_count":0,
    "byte_count":0,
    "syn_count":0,
    "fin_count":0
})

def get_flow_key(packet):
    if not packet.haslayer("IP"):
        return None
    
    src_ip=packet["IP"].src
    dst_ip=packet["IP"].dst
    protocol=packet["IP"].proto

    src_port=0
    dst_port=0

    if packet.haslayer("TCP"):
        src_port=packet["TCP"].sport
        dst_port=packet["TCP"].dport
    elif packet.haslayer("UDP"):
        src_port=packet["UDP"].sport
        dst_port=packet["UDP"].dport
    
    return (src_ip,dst_ip,src_port,dst_port,protocol)

def update_flow(packet):
    key=get_flow_key(packet)
    if not key: #not an IP packet
        return None
    
    flow=flows[key]
    current_time=time.time()

    if flow["packet_count"]==0:
        flow["start_time"]=current_time
    flow["last_seen"]=current_time
    flow["packet_count"]+=1
    flow["byte_count"]+=len(packet)

    if packet.haslayer("TCP"):
        if packet["TCP"].flags=='S':
            flow["syn_count"]+=1
        elif packet["TCP"].flags=='F':
            flow["fin_count"]+=1

def cleanup_flow():
    current_time=time.time()
    expired_keys=[]
    for key,flow in flows.items():
        if current_time-flow["last_seen"]>FLOW_TIMEOUT:
            expired_keys.append(key)
    for key in expired_keys:
        del flows[key]

def extract_flow_features(packet):
    key=get_flow_key(packet)
    if not key:
        return None

    flow=flows[key]
    duration=max(flow["last_seen"]-flow["start_time"],1)

    packet_rate=flow["packet_count"]/duration
    byte_rate=flow["byte_count"]/duration

    return [
        duration,
        flow["packet_count"],
        flow["byte_count"],
        packet_rate,
        byte_rate,
        flow["syn_count"],
        flow["fin_count"]
    ]