# main.py
import argparse
import os
import sys
import socket
from scanner.file_scanner import FileScanner
from scanner.vuln_analyzer import VulnerabilityAnalyzer
from reporting.report_generator import ReportGenerator
from utils.helpers import setup_logger

try:
    from scanner.web_scanner import WebScanner
except ImportError as e:
    if "nmap" in str(e):
        print("Error: 'python-nmap' module not found. Install it with 'pip install python-nmap'.")
        print("Note: 'nmap' binary is also required. Install it with 'sudo apt-get install nmap' (Linux).")
        print("For complete device scanning, you can proceed without nmap.")
    raise

logger = setup_logger("QSecureScan")

def validate_target(target, scan_type):
    """Validate the target based on the scan type."""
    if scan_type in ["partition", "folder", "file"]:
        if not os.path.exists(target):
            raise ValueError(f"Invalid {scan_type} path: {target} does not exist")
        if scan_type == "partition":
            if not os.path.ismount(target):
                raise ValueError(f"Target {target} is not a mounted partition")
        elif scan_type == "folder":
            if not os.path.isdir(target):
                raise ValueError(f"Target {target} is not a directory")
        elif scan_type == "file":
            if not os.path.isfile(target):
                raise ValueError(f"Target {target} is not a file")
    elif scan_type == "website":
        # Preserve original target for reporting, clean for scanning
        original_target = target
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        if not target:
            raise ValueError("Invalid website target: empty hostname")
        try:
            socket.gethostbyname(target)
        except socket.gaierror:
            logger.warning(f"Target {target} may not be resolvable")
        return original_target, target
    return target

def main():
    parser = argparse.ArgumentParser(description="Q-SecureScan: Quantum-Vulnerable Crypto Scanner")
    parser.add_argument("--target", required=True, help="Target hostname/IP (e.g., localhost, example.com) or file/folder path")
    parser.add_argument("--mode", choices=["blackbox", "complete", "partition", "folder", "file"], default="blackbox",
                        help="Scan mode: blackbox (website/server), complete (full system), partition, folder, or file")
    parser.add_argument("--output", default="reports", help="Output directory for reports")
    parser.add_argument("--login", help="Login credentials for website (username:password)")
    parser.add_argument("--no-root", action="store_true", help="Run complete/partition scan without root privileges")
    args = parser.parse_args()

    analyzer = VulnerabilityAnalyzer()
    reporter = ReportGenerator(args.output)
    items = []
    skipped_items = []

    # Determine scan type
    scan_type = args.mode
    if scan_type == "blackbox":
        original_target, target = validate_target(args.target, "website")
        try:
            scanner = WebScanner(target, args.login)
            scan_results = scanner.scan()
            items.extend(analyzer.analyze(scan_results))
            skipped_items.extend(scan_results.get("skipped_items", []))
        except Exception as e:
            logger.error(f"Failed to initialize WebScanner: {e}")
            skipped_items.append(f"Web scan: {str(e).split('(')[0].strip()}")
            sys.exit(1)
    else:
        target = validate_target(args.target, scan_type)
        try:
            file_scanner = FileScanner(target, require_root=not args.no_root, scan_type=scan_type)
            file_results = file_scanner.scan()
            items.extend(analyzer.analyze(file_results))
            skipped_items.extend(file_results.get("skipped_items", []))
        except Exception as e:
            logger.error(f"File scan failed: {e}")
            skipped_items.append(f"File scan: {str(e).split('(')[0].strip()}")
            sys.exit(1)
        
        if args.mode == "complete":
            try:
                # Use cleaned target for web scan in complete mode
                _, target = validate_target(args.target, "website") if args.target.startswith(("http://", "https://")) else (args.target, args.target)
                web_scanner = WebScanner(target, args.login)
                web_results = web_scanner.scan()
                items.extend(analyzer.analyze(web_results))
                skipped_items.extend(web_results.get("skipped_items", []))
            except Exception as e:
                logger.warning(f"Web scan failed: {e}")
                skipped_items.append(f"Web scan: {str(e).split('(')[0].strip()}")

    logger.info(f"Starting {args.mode} scan on {args.target}")
    reporter.generate_report(items, original_target if scan_type == "blackbox" else args.target, skipped_items)

if __name__ == "__main__":
    main()