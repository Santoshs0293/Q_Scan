Q-SecureScan Project Structure
This project is an enhanced version of the Q-SecureScan tool, designed to identify quantum-vulnerable cryptographic algorithms and general security vulnerabilities. It supports two scanning modes: Complete Device Scanning (files, ports, configurations) and Normal Blackbox Scanning (network-based). The backend is built with Flask, providing a robust API for managing scans and reports.
q_secure_scan/
│
├── src/
│   ├── __init__.py
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── web_scanner.py        # Handles blackbox and complete scanning
│   │   ├── vuln_analyzer.py      # Analyzes vulnerabilities and algorithms
│   │   ├── file_scanner.py       # Scans file system for complete mode
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── report_generator.py   # Generates JSON and PDF reports
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── crypto_db.py          # Database of classical algorithms
│   │   ├── helpers.py            # Utility functions
│   │   ├── ai_analyzer.py        # AI-based anomaly detection
│   ├── api/
│   │   ├── __init__.py
│   │   ├── auth.py               # JWT authentication
│   │   ├── endpoints.py          # API endpoints for scans and reports
│   ├── main.py                   # CLI entry point
│
├── tests/
│   ├── __init__.py
│   │   ├── test_web_scanner.py   # Tests for web scanner
│   │   ├── test_file_scanner.py  # Tests for file scanner
│   │   ├── test_vuln_analyzer.py # Tests for vulnerability analyzer
│   │   ├── test_report_generator.py # Tests for report generator
│   │   ├── test_api.py           # Tests for API endpoints
│
├── .vscode/
│   ├── launch.json              # VS Code debug configuration
│   ├── settings.json            # VS Code project settings
│
├── requirements.txt             # Project dependencies
├── README.md                   # Setup and usage instructions
├── .gitignore                  # Git ignore file

File Descriptions

src/scanner/web_scanner.py: Implements both blackbox and complete scanning modes, using requests for network scans and nmap for port scanning.
src/scanner/file_scanner.py: Handles file system scanning for complete mode, analyzing cryptographic libraries and configuration files.
src/scanner/vuln_analyzer.py: Analyzes scan results for quantum-vulnerable algorithms and general vulnerabilities.
src/reporting/report_generator.py: Generates reports in JSON and PDF formats, including vulnerabilities and PQC recommendations.
src/utils/crypto_db.py: Contains a database of classical algorithms (RSA, ECDH, ECDSA, AES-128, 3DES, SHA1, MD5) with quantum vulnerability status and PQC alternatives.
src/utils/helpers.py: Utility functions for logging, configuration, and entropy calculation.
src/utils/ai_analyzer.py: Implements basic AI-based anomaly detection using scikit-learn.
src/api/auth.py: Manages JWT-based authentication for API security.
src/api/endpoints.py: Defines Flask API endpoints for scan initiation, report retrieval, and recommendations.
src/main.py: CLI entry point for running scans.
tests/: Unit tests for all modules.
.vscode/: VS Code configurations for debugging and project settings.
requirements.txt: Lists dependencies (e.g., Flask, requests, reportlab, scikit-learn, python-nmap).
README.md: Detailed setup and run instructions.
.gitignore: Ignores unnecessary files (e.g., __pycache__, .venv, reports).

Source Code
src/main.py
import argparse
from scanner.web_scanner import WebScanner
from scanner.file_scanner import FileScanner
from scanner.vuln_analyzer import VulnerabilityAnalyzer
from reporting.report_generator import ReportGenerator
from utils.helpers import setup_logger

logger = setup_logger()

def main():
    parser = argparse.ArgumentParser(description="Q-SecureScan: Quantum-Vulnerable Crypto Scanner")
    parser.add_argument("--target", required=True, help="Target device URL or IP")
    parser.add_argument("--mode", choices=["blackbox", "complete"], default="blackbox", help="Scan mode: blackbox or complete")
    parser.add_argument("--output", default="reports", help="Output directory for reports")
    parser.add_argument("--login", help="Login credentials (username:password)")
    args = parser.parse_args()

    # Initialize components
    scanner = WebScanner(args.target, args.login) if args.mode == "blackbox" else FileScanner(args.target)
    analyzer = VulnerabilityAnalyzer()
    reporter = ReportGenerator(args.output)

    logger.info(f"Starting {args.mode} scan on {args.target}")
    scan_results = scanner.scan()
    vulnerabilities, crypto_algorithms = analyzer.analyze(scan_results)
    reporter.generate_report(vulnerabilities, crypto_algorithms, args.target)

if __name__ == "__main__":
    main()

src/scanner/web_scanner.py
import requests
import nmap
from flask import Flask, request, jsonify
from utils.crypto_db import is_quantum_vulnerable
from utils.helpers import setup_logger

class WebScanner:
    def __init__(self, target, login=None):
        self.target = target
        self.login = login
        self.logger = setup_logger()
        self.nm = nmap.PortScanner()
        self.app = Flask(__name__)
        self.setup_routes()

    def setup_routes(self):
        @self.app.route('/scan/blackbox', methods=['POST'])
        def scan_blackbox():
            data = request.json
            target = data.get('target', self.target)
            results = self.scan(target)
            return jsonify(results)

    def scan(self, target):
        self.logger.info(f"Performing blackbox scan on {target}")
        results = {"vulnerabilities": [], "crypto_algorithms": []}
        try:
            # HTTP/HTTPS scan
            response = requests.get(f"http://{target}", timeout=5)
            if response.status_code == 200:
                results["vulnerabilities"].append({"type": "http_access", "details": "HTTP accessible"})
            
            # SSL/TLS analysis
            ssl_response = requests.get(f"https://{target}", timeout=5, verify=False)
            if ssl_response.status_code == 200:
                crypto = self.analyze_ssl(ssl_response)
                results["crypto_algorithms"].extend(crypto)
            
            # Port scanning with nmap
            self.nm.scan(target, arguments="-sV --script ssl-enum-ciphers")
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    for port in self.nm[host][proto].keys():
                        service = self.nm[host][proto][port]
                        results["vulnerabilities"].append({
                            "type": "open_port",
                            "details": f"Port {port}/{proto}: {service['name']} ({service['product']})"
                        })
        except requests.RequestException as e:
            self.logger.error(f"Scan failed: {e}")
            results["vulnerabilities"].append({"type": "connection_error", "details": str(e)})
        return results

    def analyze_ssl(self, response):
        algorithms = ["RSA", "ECDH", "ECDSA"]  # Simplified detection
        return [{"algorithm": algo, "quantum_vulnerable": is_quantum_vulnerable(algo)} for algo in algorithms]

    def run(self):
        self.app.run(debug=False)

src/scanner/file_scanner.py
import os
import re
from utils.crypto_db import is_quantum_vulnerable
from utils.helpers import setup_logger, calculate_entropy

class FileScanner:
    def __init__(self, target):
        self.target = target
        self.logger = setup_logger()

    def scan(self):
        self.logger.info(f"Performing complete device scan on {self.target}")
        results = {"vulnerabilities": [], "crypto_algorithms": []}
        
        # Scan configuration files and libraries
        config_paths = ["/etc/ssh/sshd_config", "/etc/ipsec.conf"]  # Example paths
        for path in config_paths:
            if os.path.exists(path):
                with open(path, "r") as f:
                    content = f.read()
                    algorithms = self.detect_algorithms(content)
                    results["crypto_algorithms"].extend(algorithms)
        
        # Scan file system for encrypted files
        for root, _, files in os.walk("/"):  # Adjust root for Windows/Linux
            for file in files:
                file_path = os.path.join(root, file)
                entropy = calculate_entropy(file_path)
                if entropy and entropy > 7.0:  # High entropy suggests encryption
                    results["vulnerabilities"].append({
                        "type": "possible_encrypted_file",
                        "details": f"High entropy file: {file_path}"
                    })
        
        return results

    def detect_algorithms(self, content):
        algorithms = []
        patterns = {
            "RSA": r"\bRSA\b",
            "ECDH": r"\bECDH\b",
            "ECDSA": r"\bECDSA\b",
            "AES-128": r"\bAES-128\b",
            "3DES": r"\b3DES\b",
            "SHA1": r"\bSHA1\b",
            "MD5": r"\bMD5\b"
        }
        for algo, pattern in patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                algorithms.append({
                    "algorithm": algo,
                    "quantum_vulnerable": is_quantum_vulnerable(algo)
                })
        return algorithms

src/scanner/vuln_analyzer.py
from utils.crypto_db import is_quantum_vulnerable, get_pqc_alternative
from utils.ai_analyzer import detect_anomalies
from utils.helpers import setup_logger

class VulnerabilityAnalyzer:
    def __init__(self):
        self.logger = setup_logger()

    def analyze(self, scan_results):
        self.logger.info("Analyzing scan results")
        vulnerabilities = scan_results.get("vulnerabilities", [])
        crypto_algorithms = scan_results.get("crypto_algorithms", [])
        
        # Filter quantum-vulnerable algorithms
        quantum_vulnerable = [
            {**algo, "pqc_alternative": get_pqc_alternative(algo["algorithm"])}
            for algo in crypto_algorithms if algo.get("quantum_vulnerable")
        ]
        
        # Add location details
        for algo in quantum_vulnerable:
            algo["location"] = "Network Layer" if "port" in str(algo) else "File System"
        
        # AI-based anomaly detection
        anomalies = detect_anomalies(vulnerabilities, crypto_algorithms)
        vulnerabilities.extend(anomalies)
        
        return vulnerabilities, quantum_vulnerable

src/reporting/report_generator.py
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import json
import os
from utils.helpers import setup_logger

class ReportGenerator:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.logger = setup_logger()
        os.makedirs(output_dir, exist_ok=True)

    def generate_report(self, vulnerabilities, crypto_algorithms, target):
        self.logger.info(f"Generating report for {target}")
        
        # JSON Report
        report_data = {
            "target": target,
            "vulnerabilities": vulnerabilities,
            "quantum_vulnerable_algorithms": crypto_algorithms
        }
        json_path = os.path.join(self.output_dir, f"{target}_report.json")
        with open(json_path, "w") as f:
            json.dump(report_data, f, indent=4)
        
        # PDF Report
        pdf_path = os.path.join(self.output_dir, f"{target}_report.pdf")
        doc = SimpleDocTemplate(pdf_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        story.append(Paragraph(f"Q-SecureScan Report for {target}", styles["Title"]))
        story.append(Spacer(1, 12))
        story.append(Paragraph("Vulnerabilities:", styles["Heading2"]))
        for vuln in vulnerabilities:
            story.append(Paragraph(f"Type: {vuln['type']}, Details: {vuln['details']}", styles["Normal"]))
        story.append(Paragraph("Quantum-Vulnerable Algorithms:", styles["Heading2"]))
        for algo in crypto_algorithms:
            story.append(Paragraph(
                f"Algorithm: {algo['algorithm']}, Location: {algo['location']}, "
                f"PQC Alternative: {algo['pqc_alternative']}",
                styles["Normal"]
            ))
        
        doc.build(story)
        self.logger.info(f"Reports saved: {json_path}, {pdf_path}")

src/utils/crypto_db.py
CLASSICAL_ALGORITHMS = {
    "RSA": {"quantum_vulnerable": True, "pqc_alternative": "Kyber, FrodoKEM"},
    "ECDH": {"quantum_vulnerable": True, "pqc_alternative": "Kyber, NTRU"},
    "ECDSA": {"quantum_vulnerable": True, "pqc_alternative": "Sphincs+, Falcon"},
    "AES-128": {"quantum_vulnerable": True, "pqc_alternative": "AES-256, ChaCha20"},
    "3DES": {"quantum_vulnerable": True, "pqc_alternative": "AES-256, ChaCha20"},
    "SHA1": {"quantum_vulnerable": True, "pqc_alternative": "SHA-3"},
    "MD5": {"quantum_vulnerable": True, "pqc_alternative": "SHA-3"},
    "AES-256": {"quantum_vulnerable": False, "pqc_alternative": None},
    "SHA-256": {"quantum_vulnerable": False, "pqc_alternative": None}
}

def is_quantum_vulnerable(algorithm):
    return CLASSICAL_ALGORITHMS.get(algorithm, {}).get("quantum_vulnerable", False)

def get_pqc_alternative(algorithm):
    return CLASSICAL_ALGORITHMS.get(algorithm, {}).get("pqc_alternative", "Unknown")

src/utils/helpers.py
import logging
import math
import os

def setup_logger():
    logger = logging.getLogger("QSecureScan")
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)
    return logger

def calculate_entropy(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if not data:
            return None
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        entropy = 0
        for count in byte_counts:
            if count:
                prob = count / len(data)
                entropy -= prob * math.log2(prob)
        return entropy
    except Exception as e:
        logger = setup_logger()
        logger.error(f"Entropy calculation failed for {file_path}: {e}")
        return None

src/utils/ai_analyzer.py
from sklearn.ensemble import IsolationForest
from utils.helpers import setup_logger

def detect_anomalies(vulnerabilities, crypto_algorithms):
    logger = setup_logger()
    logger.info("Running AI-based anomaly detection")
    
    # Simplified feature extraction
    data = []
    for vuln in vulnerabilities:
        data.append([len(vuln["details"]), 1 if "error" in vuln["type"] else 0])
    for algo in crypto_algorithms:
        data.append([len(algo["algorithm"]), 1 if algo["quantum_vulnerable"] else 0])
    
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
            if i < len(vulnerabilities):
                anomalies.append({
                    "type": "anomaly",
                    "details": f"Anomalous vulnerability: {vulnerabilities[i]['details']}"
                })
            else:
                algo_idx = i - len(vulnerabilities)
                anomalies.append({
                    "type": "anomaly",
                    "details": f"Anomalous algorithm: {crypto_algorithms[algo_idx]['algorithm']}"
                })
    return anomalies

src/api/auth.py
from flask import Blueprint, request, jsonify
import jwt
import datetime
from utils.helpers import setup_logger

auth_bp = Blueprint('auth', __name__)
SECRET_KEY = "your-secret-key"  # Replace with secure key
logger = setup_logger()

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    # Simplified authentication (replace with database check)
    if username == "admin" and password == "password":  # Example credentials
        token = jwt.encode({
            'user': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, SECRET_KEY, algorithm="HS256")
        return jsonify({"token": token})
    return jsonify({"error": "Invalid credentials"}), 401

def token_required(f):
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token is missing"}), 401
        try:
            jwt.decode(token.replace("Bearer ", ""), SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorator

src/api/endpoints.py
from flask import Blueprint, request, jsonify
from scanner.web_scanner import WebScanner
from scanner.file_scanner import FileScanner
from scanner.vuln_analyzer import VulnerabilityAnalyzer
from reporting.report_generator import ReportGenerator
from .auth import token_required
from utils.helpers import setup_logger

api_bp = Blueprint('api', __name__)
logger = setup_logger()

@api_bp.route('/scan', methods=['POST'])
@token_required
def initiate_scan():
    data = request.json
    target = data.get('target')
    mode = data.get('mode', 'blackbox')
    login = data.get('login')
    output = data.get('output', 'reports')
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    scanner = WebScanner(target, login) if mode == "blackbox" else FileScanner(target)
    analyzer = VulnerabilityAnalyzer()
    reporter = ReportGenerator(output)
    
    logger.info(f"Initiating {mode} scan on {target}")
    scan_results = scanner.scan()
    vulnerabilities, crypto_algorithms = analyzer.analyze(scan_results)
    reporter.generate_report(vulnerabilities, crypto_algorithms, target)
    
    return jsonify({
        "status": "success",
        "vulnerabilities": vulnerabilities,
        "crypto_algorithms": crypto_algorithms
    })

@api_bp.route('/reports/<target>', methods=['GET'])
@token_required
def get_report(target):
    report_path = f"reports/{target}_report.json"
    if not os.path.exists(report_path):
        return jsonify({"error": "Report not found"}), 404
    with open(report_path, "r") as f:
        report = json.load(f)
    return jsonify(report)

tests/test_web_scanner.py
import unittest
from scanner.web_scanner import WebScanner

class TestWebScanner(unittest.TestCase):
    def test_blackbox_scan(self):
        scanner = WebScanner("example.com")
        results = scanner.scan()
        self.assertIn("vulnerabilities", results)
        self.assertIn("crypto_algorithms", results)

if __name__ == "__main__":
    unittest.main()

tests/test_file_scanner.py
import unittest
from scanner.file_scanner import FileScanner

class TestFileScanner(unittest.TestCase):
    def test_complete_scan(self):
        scanner = FileScanner("localhost")
        results = scanner.scan()
        self.assertIn("vulnerabilities", results)
        self.assertIn("crypto_algorithms", results)

if __name__ == "__main__":
    unittest.main()

tests/test_vuln_analyzer.py
import unittest
from scanner.vuln_analyzer import VulnerabilityAnalyzer

class TestVulnerabilityAnalyzer(unittest.TestCase):
    def test_analyze(self):
        analyzer = VulnerabilityAnalyzer()
        scan_results = {
            "vulnerabilities": [{"type": "http_access", "details": "HTTP accessible"}],
            "crypto_algorithms": [{"algorithm": "RSA", "quantum_vulnerable": True}]
        }
        vulns, crypto = analyzer.analyze(scan_results)
        self.assertEqual(len(crypto), 1)
        self.assertEqual(crypto[0]["algorithm"], "RSA")
        self.assertIn("pqc_alternative", crypto[0])

if __name__ == "__main__":
    unittest.main()

tests/test_report_generator.py
import unittest
import os
from reporting.report_generator import ReportGenerator

class TestReportGenerator(unittest.TestCase):
    def test_generate_report(self):
        reporter = ReportGenerator("test_reports")
        vulnerabilities = [{"type": "http_access", "details": "HTTP accessible"}]
        crypto_algorithms = [{
            "algorithm": "RSA",
            "quantum_vulnerable": True,
            "location": "Network Layer",
            "pqc_alternative": "Kyber, FrodoKEM"
        }]
        reporter.generate_report(vulnerabilities, crypto_algorithms, "example.com")
        self.assertTrue(os.path.exists("test_reports/example.com_report.json"))
        self.assertTrue(os.path.exists("test_reports/example.com_report.pdf"))

if __name__ == "__main__":
    unittest.main()

tests/test_api.py
import unittest
from flask import Flask
from src.api.endpoints import api_bp
from src.api.auth import auth_bp

class TestAPI(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.register_blueprint(api_bp)
        self.app.register_blueprint(auth_bp)
        self.client = self.app.test_client()

    def test_login(self):
        response = self.client.post('/login', json={"username": "admin", "password": "password"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("token", response.json)

if __name__ == "__main__":
    unittest.main()

.vscode/launch.json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Run Flask API",
            "type": "python",
            "request": "launch",
            "program": "${workspaceFolder}/src/web_scanner.py",
            "console": "integratedTerminal",
            "justMyCode": true
        },
        {
            "name": "Run CLI",
            "type": "python",
            "request": "launch",
            "program": "${workspaceFolder}/src/main.py",
            "args": ["--target", "example.com", "--mode", "blackbox"],
            "console": "integratedTerminal",
            "justMyCode": true
        }
    ]
}

.vscode/settings.json
{
    "python.pythonPath": ".venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true,
    "python.formatting.provider": "black"
}

requirements.txt
flask==2.3.3
requests==2.31.0
reportlab==4.0.7
python-nmap==0.7.1
scikit-learn==1.3.2
pyjwt==2.8.0

README.md
# Q-SecureScan

An automated tool to identify quantum-vulnerable cryptographic algorithms (RSA, ECDH, ECDSA, AES-128, 3DES, SHA1, MD5) and general security vulnerabilities. Supports two modes: Complete Device Scanning (files, ports, configurations) and Normal Blackbox Scanning (network-based).

## Setup in VS Code

1. **Clone the Repository**:
   ```bash
   git clone <repo-url>
   cd q_secure_scan


Create a Virtual Environment:
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate      # Windows


Install Dependencies:
pip install -r requirements.txt


Install Nmap:

Linux: sudo apt-get install nmap
Windows: Download and install from Nmap website
Ensure nmap is in your system PATH.


Configure VS Code:

Open the project in VS Code: code .
Ensure the .vscode folder is present with launch.json and settings.json.
Select the Python interpreter from .venv (Ctrl+Shift+P, "Python: Select Interpreter").



Running the Application

Run the Flask API:

In VS Code, use the "Run Flask API" debug configuration.

Or, manually run:
python3 src/scanner/web_scanner.py


Access the API at http://localhost:5000.



Run the CLI:

For blackbox scanning:
python src/main.py --target example.com --mode blackbox --output reports


For complete device scanning (requires root/admin privileges):
sudo python3 src/main.py --target localhost --mode complete --output reports




API Usage:

Login:
curl -X POST http://localhost:5000/login -H "Content-Type: application/json" -d '{"username":"admin","password":"password"}'


Initiate Scan:
curl -X POST http://localhost:5000/scan -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"target":"example.com","mode":"blackbox"}'


Get Report:
curl -X GET http://localhost:5000/reports/example.com -H "Authorization: Bearer <token>"





Features

Complete Device Scanning: Analyzes files, ports, and configurations for quantum-vulnerable algorithms and vulnerabilities.
Normal Blackbox Scanning: Performs network-based scanning using HTTP/HTTPS and nmap.
API Endpoints: Securely manage scans and reports via RESTful APIs with JWT authentication.
Reports: Generates JSON and PDF reports with vulnerabilities and PQC recommendations.
AI Integration: Uses scikit-learn for anomaly detection in scan results.

Notes

Replace SECRET_KEY in src/api/auth.py with a secure key.
Complete device scanning may require root/admin privileges for file system access.
Ensure nmap is installed and accessible for port scanning.





Run Scans:
Folder:
bash


Run

Copy
python3 src/main.py --target "/home/santosh/Documents/Documents (1)/gem_doc" --mode folder --output reports
Complete:
bash

Run

Copy
sudo python3 src/main.py --target localhost --mode complete --output reports
Partition (e.g., /mnt/data):
bash

Run

Copy
sudo python3 src/main.py --target /mnt/data --mode partition --output reports
File (e.g., /etc/ssh/sshd_config):
bash

Run

Copy
sudo python3 src/main.py --target /etc/ssh/sshd_config --mode file --output reports
Blackbox:
bash


Run

Copy
python3 src/main.py --target https://localhost --mode blackbox --output reports
# Q_Scan
# Q_Scan
