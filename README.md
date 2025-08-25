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
