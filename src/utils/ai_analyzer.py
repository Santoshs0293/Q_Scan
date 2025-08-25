#ai_analyzer.py
from sklearn.ensemble import IsolationForest
from utils.helpers import setup_logger

def detect_anomalies(items):
    logger = setup_logger()
    logger.info("Running AI-based anomaly detection")
    
    # Feature extraction for anomaly detection
    data = []
    item_ids = []
    for item in items:
        entropy = item["analysis"].get("entropy", 0) or 0
        is_encrypted = 1 if "encrypted" in item["analysis"].get("heuristics", "").lower() else 0
        is_compressed = 1 if "compressed" in item["analysis"].get("heuristics", "").lower() else 0
        is_tls = 1 if item["type"] in ["protocol", "port"] and "TLS" in item["analysis"].get("heuristics", "") else 0
        is_ssh = 1 if item["type"] == "port" and "SSH" in item["analysis"].get("heuristics", "") else 0
        data.append([entropy, is_encrypted, is_compressed, is_tls, is_ssh])
        item_ids.append(item["id"])
    
    if not data:
        return []
    
    # Train Isolation Forest model
    model = IsolationForest(contamination=0.1)
    model.fit(data)
    predictions = model.predict(data)
    
    # Identify anomalies
    anomalies = []
    for i, pred in enumerate(predictions):
        if pred == -1:  # Anomaly detected
            anomalies.append({
                "id": item_ids[i],
                "details": f"Anomalous item: {item_ids[i]}"
            })
    return anomalies