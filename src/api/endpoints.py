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