from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np

TRAINING_LIMIT=100
ANOMALY_THRESHOLD=-0.15

scaler=StandardScaler()

model=IsolationForest(
    n_estimators=200,
    contamination=0.03,
    random_state=42
)

model_trained=False
training_data=[]

def train_model():
    global model_trained
    X=np.array([training_data])
    X_scaled=scaler.fit_transform(X)
    model.fit(X_scaled)
    model_trained=True
    print(" ===== [ML] Model trained succesfully. =====")

def analyze_packet_ml(features):
    global training_data

    if not model_trained:
        training_data.append(features)
        if len(training_data)>=TRAINING_LIMIT:
            train_model()
        return None
    
    X=np.array([features])
    X_scaled=scaler(X)
    anomaly_score=model.decision_function(X_scaled)[0]
    if anomaly_score<ANOMALY_THRESHOLD:
        return anomaly_score
    return None