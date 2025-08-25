import os
import re
import json
import mimetypes
import mysql.connector
import psycopg2
from utils.crypto_db import is_quantum_vulnerable, get_pqc_alternative, get_security_level, get_severity, ALGORITHMS
from utils.helpers import setup_logger, calculate_entropy

class FileScanner:
    def __init__(self, target, require_root=True, scan_type="complete", policies=None):
        self.target = target
        self.scan_type = scan_type  # complete, partition, folder, or file
        self.logger = setup_logger("FileScanner")
        self.skip_dirs = ["/proc", "/sys", "/dev", "/run"]
        self.skip_files = ["/swapfile"]
        self.require_root = require_root
        self.policies = policies or [
            {"name": "Minimum Key Strength", "rule": lambda algo, bits: not bits or (algo in ["RSA", "DSA", "DH"] and bits < 2048) or (algo in ["AES", "Blowfish", "Twofish"] and bits < 128), "severity": "High", "compliance": "GDPR, PCI-DSS"},
            {"name": "Deprecated Algorithms", "rule": lambda algo, bits: algo in ["MD5", "SHA1", "DES", "3DES", "RC4"], "severity": "High", "compliance": "GDPR, PCI-DSS"}
        ]
        self.cbom = {"cryptographic_assets": []}  # Cryptographic Bill of Materials
        mimetypes.init()

    def scan(self):
        self.logger.info(f"Performing {self.scan_type} scan on {self.target}")
        results = {"items": [], "skipped_items": [], "cbom": self.cbom}
        
        # Define scan targets based on scan_type
        if self.scan_type == "file":
            scan_files = [self.target]
            scan_dirs = []
        elif self.scan_type == "folder":
            scan_files = []
            scan_dirs = [self.target]
        elif self.scan_type == "partition":
            scan_files = []
            scan_dirs = [self.target]
        else:  # complete
            scan_files = ["/etc/ssh/sshd_config", "/etc/ipsec.conf", "/etc/my.cnf", "/etc/postgresql/pg_hba.conf"]
            scan_dirs = ["/etc", "/home", "/var"] if self.require_root else [os.path.expanduser("~")]

        # Scan specific configuration files (for complete mode or explicit file scan)
        for path in scan_files:
            if not os.path.exists(path):
                results["skipped_items"].append(f"{path}: File does not exist")
                self.logger.warning(f"Skipping {path}: File does not exist")
                continue
            if self.require_root and os.geteuid() != 0:
                results["skipped_items"].append(f"{path}: Root privileges required")
                self.logger.warning(f"Skipping {path}: Root privileges required")
                continue
            try:
                with open(path, "r") as f:
                    content = f.read()
                    algorithms = self.detect_algorithms(content)
                    analysis = self.analyze_file(path)
                    policy_violations = self.check_policies(algorithms, path)
                    remediation = self.get_remediation_guidance(algorithms, path)
                    self.add_to_cbom(path, "file", algorithms, analysis, policy_violations)
                    results["items"].append({
                        "id": path,
                        "type": "file",
                        "algorithms": algorithms,
                        "analysis": analysis,
                        "policy_violations": policy_violations,
                        "pqc_recommendation": self.get_pqc_recommendation(algorithms, analysis["entropy"] > 7.0 if analysis["entropy"] else False, path),
                        "remediation_guidance": remediation
                    })
            except PermissionError:
                results["skipped_items"].append(f"{path}: Permission denied")
                self.logger.warning(f"Permission denied for {path}, skipping")
            except Exception as e:
                results["skipped_items"].append(f"{path}: {str(e).split('(')[0].strip()}")
                self.logger.warning(f"Failed to read {path}: {e}")
        
        # Scan directories (for complete, partition, or folder modes)
        for scan_dir in scan_dirs:
            if not os.path.exists(scan_dir):
                results["skipped_items"].append(f"{scan_dir}: Directory does not exist")
                self.logger.warning(f"Skipping {scan_dir}: Directory does not exist")
                continue
            for root, dirs, files in os.walk(scan_dir):
                if any(root.startswith(d) for d in self.skip_dirs) and self.scan_type == "complete":
                    continue
                for file in files:
                    file_path = os.path.join(root, file)
                    if file_path in self.skip_files and self.scan_type == "complete":
                        results["skipped_items"].append(f"{file_path}: System file skipped")
                        self.logger.warning(f"Skipping system file: {file_path}")
                        continue
                    try:
                        analysis = self.analyze_file(file_path)
                        algorithms = []
                        if analysis["entropy"] and analysis["entropy"] > 7.0:
                            algorithms = self.detect_code_issues(file_path)
                        else:
                            with open(file_path, "r", errors="ignore") as f:
                                content = f.read()
                                algorithms = self.detect_algorithms(content)
                        policy_violations = self.check_policies(algorithms, file_path)
                        remediation = self.get_remediation_guidance(algorithms, file_path)
                        self.add_to_cbom(file_path, "file", algorithms, analysis, policy_violations)
                        results["items"].append({
                            "id": file_path,
                            "type": "file",
                            "algorithms": algorithms,
                            "analysis": analysis,
                            "policy_violations": policy_violations,
                            "pqc_recommendation": self.get_pqc_recommendation(algorithms, analysis["entropy"] > 7.0 if analysis["entropy"] else False, file_path),
                            "remediation_guidance": remediation
                        })
                    except PermissionError:
                        results["skipped_items"].append(f"{file_path}: Permission denied")
                        self.logger.warning(f"Permission denied for {file_path}, skipping")
                    except Exception as e:
                        results["skipped_items"].append(f"{file_path}: {str(e).split('(')[0].strip()}")
                        self.logger.warning(f"Failed to analyze {file_path}: {e}")

        # Database configuration scanning (basic)
        self.scan_database_configs(results)
        
        # Save CBOM to file
        cbom_path = os.path.join(self.target if os.path.isdir(self.target) else os.path.dirname(self.target), "cbom.json")
        with open(cbom_path, "w") as f:
            json.dump(self.cbom, f, indent=4)
        self.logger.info(f"CBOM saved to {cbom_path}")

        return results

    def scan_database_configs(self, results):
        # Basic database config scanning for MySQL and PostgreSQL
        db_configs = {
            "mysql": "/etc/my.cnf",
            "postgresql": "/etc/postgresql/pg_hba.conf"
        }
        for db_type, config_path in db_configs.items():
            if not os.path.exists(config_path):
                results["skipped_items"].append(f"{config_path}: Database config not found")
                self.logger.warning(f"Skipping {config_path}: Database config not found")
                continue
            try:
                with open(config_path, "r") as f:
                    content = f.read()
                    algorithms = self.detect_algorithms(content)
                    analysis = self.analyze_file(config_path)
                    policy_violations = self.check_policies(algorithms, config_path)
                    remediation = self.get_remediation_guidance(algorithms, config_path)
                    self.add_to_cbom(config_path, f"{db_type}_config", algorithms, analysis, policy_violations)
                    results["items"].append({
                        "id": config_path,
                        "type": f"{db_type}_config",
                        "algorithms": algorithms,
                        "analysis": analysis,
                        "policy_violations": policy_violations,
                        "pqc_recommendation": self.get_pqc_recommendation(algorithms, analysis["entropy"] > 7.0 if analysis["entropy"] else False, config_path),
                        "remediation_guidance": remediation
                    })
            except Exception as e:
                results["skipped_items"].append(f"{config_path}: {str(e).split('(')[0].strip()}")
                self.logger.warning(f"Failed to analyze {config_path}: {e}")

    def detect_algorithms(self, content):
        found = []
        for base in ALGORITHMS.keys():
            pattern = fr"\b{re.escape(base)}[- ]?(\d+)?\b"
            for m in re.finditer(pattern, content, re.IGNORECASE):
                bits = int(m.group(1)) if m.group(1) else None
                full = f"{base}-{bits}" if bits else base
                found.append({"base": base, "bits": bits, "full": full})
        # Deduplicate
        unique = {f['full']: f for f in found}.values()
        return list(unique)

    def detect_code_issues(self, file_path):
        algorithms = []
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()
                # Detect hardcoded keys or weak algorithms in code
                patterns = [
                    (r"(?i)\b(private|public)\s+key\b.*=.*['\"]([0-9a-fA-F]+)['\"]", "Hardcoded Key"),
                    (r"(?i)\b(RSA|DES|MD5|SHA1)\b", "Weak Algorithm in Code")
                ]
                for pattern, issue in patterns:
                    for m in re.finditer(pattern, content, re.IGNORECASE):
                        if issue == "Hardcoded Key":
                            algorithms.append({"base": "Hardcoded Key", "bits": None, "full": "Hardcoded Key"})
                        else:
                            base = m.group(1)
                            algorithms.append({"base": base, "bits": None, "full": base})
            return algorithms
        except Exception:
            return []

    def analyze_file(self, file_path):
        analysis = {
            "entropy": calculate_entropy(file_path),
            "header": self.get_file_header(file_path),
            "extension": os.path.splitext(file_path)[1].lower(),
            "metadata": self.get_metadata(file_path),
            "encryption_markers": self.detect_encryption_markers(file_path),
            "heuristics": None
        }
        if analysis["entropy"] and analysis["entropy"] > 7.0:
            if analysis["extension"] in [".gz", ".zip"]:
                analysis["heuristics"] = "Likely compressed file"
            elif analysis["header"] == "unknown" or analysis["encryption_markers"]:
                analysis["heuristics"] = "Likely encrypted file"
            else:
                analysis["heuristics"] = "High entropy, possible encryption or compression"
        else:
            analysis["heuristics"] = "Low entropy, no encryption detected"
        return analysis

    def get_file_header(self, file_path):
        try:
            with open(file_path, "rb") as f:
                header = f.read(8)
                if header.startswith(b"\x1f\x8b"):
                    return "gzip"
                elif header.startswith(b"PK\x03\x04"):
                    return "zip"
                elif header.startswith(b"Salted__"):
                    return "openssl"
                return "unknown"
        except Exception:
            return "unknown"

    def get_metadata(self, file_path):
        try:
            stat = os.stat(file_path)
            mime, _ = mimetypes.guess_type(file_path)
            return {
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "mime_type": mime or "unknown"
            }
        except Exception:
            return {"size": 0, "mtime": 0, "mime_type": "unknown"}

    def detect_encryption_markers(self, file_path):
        try:
            with open(file_path, "rb") as f:
                content = f.read(1024)
                if b"Salted__" in content:
                    return "OpenSSL encryption"
                return None
        except Exception:
            return None

    def check_policies(self, algorithms, file_path):
        violations = []
        for algo in algorithms:
            for policy in self.policies:
                if policy["rule"](algo["base"], algo["bits"]):
                    violations.append({
                        "policy_name": policy["name"],
                        "severity": policy["severity"],
                        "compliance": policy["compliance"],
                        "details": f"{algo['full']} violates {policy['name']}"
                    })
        if not algorithms and os.path.splitext(file_path)[1].lower() in [".pem", ".key", ".crt"]:
            violations.append({
                "policy_name": "Potential Cryptographic Asset",
                "severity": "Medium",
                "compliance": "GDPR, PCI-DSS",
                "details": "File extension suggests cryptographic material; verify usage"
            })
        return violations

    def get_remediation_guidance(self, algorithms, file_path):
        guidance = []
        for algo in algorithms:
            base = algo["base"]
            if base == "Hardcoded Key":
                guidance.append(f"Remove hardcoded key in {file_path}; use secure key management (e.g., HashiCorp Vault)")
            elif is_quantum_vulnerable(base, algo["bits"]):
                alt = get_pqc_alternative(base, algo["bits"])
                if "ssh" in file_path.lower():
                    guidance.append(f"Update {file_path} to use {alt} (e.g., `Ciphers aes256-ctr` in sshd_config)")
                elif "mysql" in file_path.lower() or "postgresql" in file_path.lower():
                    guidance.append(f"Configure {file_path} to use {alt} (e.g., set `ssl_cipher={alt}` in MySQL/PostgreSQL config)")
                else:
                    guidance.append(f"Replace {algo['full']} with {alt} in {file_path}")
        if not algorithms and os.path.splitext(file_path)[1].lower() in [".pem", ".key", ".crt"]:
            guidance.append(f"Verify {file_path} uses quantum-resistant algorithms; consider CRYSTALS-Kyber or Dilithium")
        return "; ".join(guidance) if guidance else "No remediation required"

    def add_to_cbom(self, item_id, item_type, algorithms, analysis, policy_violations):
        asset = {
            "id": item_id,
            "type": item_type,
            "algorithms": algorithms,
            "metadata": analysis["metadata"],
            "encryption_markers": analysis["encryption_markers"],
            "heuristics": analysis["heuristics"],
            "policy_violations": policy_violations,
            "compliance_impact": [v["compliance"] for v in policy_violations] if policy_violations else []
        }
        self.cbom["cryptographic_assets"].append(asset)

    def get_pqc_recommendation(self, algorithms, is_high_entropy=False, file_path=None):
        if is_high_entropy and not algorithms:
            extension = os.path.splitext(file_path)[1].lower() if file_path else ""
            header = self.get_file_header(file_path) if file_path else "unknown"
            if extension in [".gz", ".zip"]:
                return "Severity: Low; Compressed file detected; no quantum-resistant migration needed unless encryption is also used"
            elif extension in [".pem", ".key", ".crt"]:
                return "Severity: High; Likely cryptographic key or certificate; migrate to quantum-resistant algorithms like CRYSTALS-Kyber or CRYSTALS-Dilithium"
            elif header == "openssl":
                return "Severity: High; OpenSSL-encrypted file detected; migrate to quantum-resistant algorithms like AES-256 or CRYSTALS-Kyber"
            else:
                return "Severity: Medium; High-entropy file, possibly encrypted; consider migrating to quantum-resistant algorithms like AES-256 or CRYSTALS-Kyber"
        if not algorithms:
            return "Severity: Low; No quantum-vulnerable algorithms detected"
        recommendations = []
        for a in algorithms:
            base = a["base"]
            bits = a["bits"]
            severity = get_severity(base, bits)
            if is_quantum_vulnerable(base, bits):
                alt = get_pqc_alternative(base, bits)
                sec = get_security_level(base, bits)
                pqc_level = "level 1 (e.g., Kyber-512)" if sec <= 128 else "level 3 (e.g., Kyber-768)" if sec <= 192 else "level 5 (e.g., Kyber-1024)"
                recommendations.append(f"Severity: {severity}; Migrate {a['full']} (~{sec} bits security) to {alt} at {pqc_level}")
            else:
                msg = f"Severity: {severity}; Safe: {a['full']} is quantum-resistant"
                if base in ["CRYSTALS-Kyber", "Kyber", "CRYSTALS-Dilithium", "Dilithium", "FALCON", "SPHINCS+", "XMSS", "LMS", "BIKE", "HQC", "Classic McEliece", "NTRU", "FrodoKEM"]:
                    msg += " (Post-Quantum Cryptography)"
                recommendations.append(msg)
        return "; ".join(recommendations) if recommendations else "Severity: Low; No quantum-vulnerable algorithms detected"