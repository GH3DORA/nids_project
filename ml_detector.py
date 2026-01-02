from sklearn.ensemble import IsolationForest
import numpy as np

TRAINING_LIMIT=100
ANOMALY_THRESHOLD=0.0

model=IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42
)

model_trained=False
training_data=[]
def train_model():
    global model_trained
    model.fit(training_data)
    model_trained=True
    print(" ===== [ML] Model trained succesfully. =====")

def analyze_packet_ml(combined_features):
    global training_data
    if not model_trained:
        training_data.append(combined_features)
        if len(training_data)>=TRAINING_LIMIT:
            train_model()
        return None
    np_features=np.array([combined_features])
    anomaly_score=model.decision_function(np_features)[0]
    if anomaly_score<ANOMALY_THRESHOLD:
        return anomaly_score
    return None


# ========== OLD FEATURE EXTRACTION, INDIVIDUAL PACKET BASED ==========
# def extract_features(packet):
#     if not packet.haslayer("IP"):
#         return
    
#     packet_size=len(packet)
#     protocol=packet["IP"].proto
#     src_port=0
#     dst_port=0
    
#     if (packet.haslayer("TCP")):
#         src_port=packet["TCP"].sport
#         dst_port=packet["TCP"].dport
#     elif (packet.haslayer("UDP")):
#         src_port=packet["UDP"].sport
#         dst_port=packet["UDP"].dport

#     return [
#         packet_size,
#         protocol,
#         src_port,
#         dst_port
#     ]