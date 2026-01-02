from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np

TRAINING_LIMIT=10
ANOMALY_THRESHOLD=-0.15

models={}
scalers={}
training_buffers={}
trained={}

classes=["ICMP","WEB","LOGIN","TCP_OTHER","UDP"]

for c in classes:
    models[c]=IsolationForest(
        n_estimators=150,
        contamination=0.03,
        random_state=42
    )
    scalers[c]=StandardScaler()
    training_buffers[c]=[]
    trained[c]=False

def train_model(traffic_class):
    X=np.array(training_buffers[traffic_class])
    X_scaled=scalers[traffic_class].fit_transform(X)
    models[traffic_class].fit(X_scaled)
    trained[traffic_class]=True
    print(f"[ML] Model trained for {traffic_class}")

def analyze_packet_ml(features,traffic_class):
    if traffic_class not in models:
        return None
    if not trained[traffic_class]:
        training_buffers[traffic_class].append(features)
        if len(training_buffers[traffic_class])>=TRAINING_LIMIT:
            train_model(traffic_class)
        return None
    X=np.array([features])
    X_scaled=scalers[traffic_class].transform(X)

    anomaly_score=models[traffic_class].decision_function(X_scaled)[0]
    if anomaly_score<ANOMALY_THRESHOLD:
        return anomaly_score
    return None