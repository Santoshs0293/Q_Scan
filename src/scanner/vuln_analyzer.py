#vuln_analyzer.py
from utils.ai_analyzer import detect_anomalies
from utils.helpers import setup_logger

class VulnerabilityAnalyzer:
    def __init__(self):
        self.logger = setup_logger()

    def analyze(self, scan_results):
        self.logger.info("Analyzing scan results")
        items = scan_results.get("items", [])
        
        # Run AI-based anomaly detection
        anomalies = detect_anomalies(items)
        
        # Update items with anomaly information
        for item in items:
            item_id = item["id"]
            for anomaly in anomalies:
                if anomaly["id"] == item_id:
                    item["is_anomaly"] = True
                    item["anomaly_details"] = anomaly["details"]
        
        return items