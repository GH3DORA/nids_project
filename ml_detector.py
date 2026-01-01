from sklearn.ensemble import IsolationForest
import numpy as np

TRAINING_PACKET_LIMIT=200
ANOMALY_THRESHOLD=0.25

model=IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42
)

def extract_features(packet):
    packet_size=len(packet)
    protocol=0
    src_port=0
    dst_port=0

    if (packet.haslayer("IP")):
        protocol=packet["IP"].proto

    if (packet.haslayer("TCP")):
        src_port=packet["TCP"].sport
        dst_port=packet["TCP"].dport
    elif (packet.haslayer("UDP")):
        src_port=packet["UDP"].sport
        dst_port=packet["UDP"].dport

    return [
        packet_size,
        protocol,
        src_port,
        dst_port
    ]

model_trained=False
training_data=[]
def train_model():
    global model_trained
    model.fit(training_data)
    model_trained=True
    print(" ===== [ML] Model trained succesfully. =====")

def analyze_packet_ml(packet):
    global training_data
    features=extract_features(packet)
    if not model_trained:
        training_data.append(features)
        if len(training_data)>=TRAINING_PACKET_LIMIT:
            train_model()
        return None
    np_features=np.array([features])
    anomaly_score=model.decision_function(np_features)[0]
    if anomaly_score<ANOMALY_THRESHOLD:
        return{
            "Anomaly_score" : anomaly_score,
            "Packet_size" : features[0],
            "Protocol" : features[1],
            "Source_port" : features[2],
            "Destination_port" : features[3]
        }
    return None