# import os
# import re
# from utils.crypto_db import is_quantum_vulnerable
# from utils.helpers import setup_logger, calculate_entropy

# class FileScanner:
#     def __init__(self, target, require_root=True):
#         self.target = target
#         self.logger = setup_logger()
#         self.skip_dirs = ["/proc", "/sys", "/dev", "/run"]
#         self.skip_files = ["/swapfile"]
#         self.require_root = require_root

#     def scan(self):
#         self.logger.info(f"Performing complete device scan on {self.target}")
#         results = {"vulnerabilities": [], "crypto_algorithms": [], "skipped_files": []}
        
#         # Scan configuration files
#         config_paths = ["/etc/ssh/sshd_config", "/etc/ipsec.conf"]
#         for path in config_paths:
#             if not os.path.exists(path):
#                 continue
#             if self.require_root and os.geteuid() != 0:
#                 results["skipped_files"].append(path)
#                 self.logger.warning(f"Skipping {path}: Root privileges required")
#                 continue
#             try:
#                 with open(path, "r") as f:
#                     content = f.read()
#                     algorithms = self.detect_algorithms(content)
#                     results["crypto_algorithms"].extend(algorithms)
#             except PermissionError:
#                 results["skipped_files"].append(path)
#                 self.logger.warning(f"Permission denied for {path}, skipping")
#             except Exception as e:
#                 results["skipped_files"].append(path)
#                 self.logger.warning(f"Failed to read {path}: {e}")
        
#         # Scan file system for encrypted files
#         scan_dirs = ["/etc", "/home", "/var"] if self.require_root else [os.path.expanduser("~")]
#         for scan_dir in scan_dirs:
#             if not os.path.exists(scan_dir):
#                 continue
#             for root, dirs, files in os.walk(scan_dir):
#                 if any(root.startswith(d) for d in self.skip_dirs):
#                     continue
#                 for file in files:
#                     file_path = os.path.join(root, file)
#                     if file_path in self.skip_files:
#                         results["skipped_files"].append(file_path)
#                         self.logger.warning(f"Skipping system file: {file_path}")
#                         continue
#                     entropy = calculate_entropy(file_path)
#                     if entropy and entropy > 7.0:
#                         results["vulnerabilities"].append({
#                             "type": "possible_encrypted_file",
#                             "details": f"High entropy file: {file_path} (entropy: {entropy:.2f})"
#                         })
        
#         return results

#     def detect_algorithms(self, content):
#         algorithms = []
#         patterns = {
#             "RSA": r"\bRSA\b",
#             "ECDH": r"\bECDH\b",
#             "ECDSA": r"\bECDSA\b",
#             "AES-128": r"\bAES-128\b",
#             "3DES": r"\b3DES\b",
#             "SHA1": r"\bSHA1\b",
#             "MD5": r"\bMD5\b"
#         }
#         for algo, pattern in patterns.items():
#             if re.search(pattern, content, re.IGNORECASE):
#                 algorithms.append({
#                     "algorithm": algo,
#                     "quantum_vulnerable": is_quantum_vulnerable(algo)
#                 })
#         return algorithms


#file_scanner.py
import os
import re
import mimetypes
from utils.crypto_db import is_quantum_vulnerable, get_pqc_alternative, CLASSICAL_ALGORITHMS
from utils.helpers import setup_logger, calculate_entropy

class FileScanner:
    def __init__(self, target, require_root=True, scan_type="complete"):
        self.target = target
        self.scan_type = scan_type  # complete, partition, folder, or file
        self.logger = setup_logger("FileScanner")
        self.skip_dirs = ["/proc", "/sys", "/dev", "/run"]
        self.skip_files = ["/swapfile"]
        self.require_root = require_root
        mimetypes.init()

    def scan(self):
        self.logger.info(f"Performing {self.scan_type} scan on {self.target}")
        results = {"items": [], "skipped_items": []}
        
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
            scan_files = ["/etc/ssh/sshd_config", "/etc/ipsec.conf"]
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
                    results["items"].append({
                        "id": path,
                        "type": "file",
                        "algorithms": algorithms,
                        "analysis": {
                            "entropy": None,
                            "header": "text",
                            "extension": os.path.splitext(path)[1],
                            "metadata": self.get_metadata(path),
                            "encryption_markers": None,
                            "heuristics": "Configuration file, no encryption"
                        },
                        "pqc_recommendation": self.get_pqc_recommendation(algorithms)
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
                        if analysis["entropy"] and analysis["entropy"] > 7.0:
                            results["items"].append({
                                "id": file_path,
                                "type": "file",
                                "algorithms": [],
                                "analysis": analysis,
                                "pqc_recommendation": self.get_pqc_recommendation([], is_high_entropy=True, file_path=file_path)
                            })
                    except PermissionError:
                        results["skipped_items"].append(f"{file_path}: Permission denied")
                        self.logger.warning(f"Permission denied for {file_path}, skipping")
                    except Exception as e:
                        results["skipped_items"].append(f"{file_path}: {str(e).split('(')[0].strip()}")
                        self.logger.warning(f"Failed to analyze {file_path}: {e}")
        
        return results

    def detect_algorithms(self, content):
        algorithms = []
        for algo in CLASSICAL_ALGORITHMS.keys():
            # Use exact match with word boundaries, case-insensitive
            pattern = fr"\b{re.escape(algo)}\b"
            if re.search(pattern, content, re.IGNORECASE) and algo not in algorithms:
                algorithms.append(algo)
        return algorithms

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

    def get_pqc_recommendation(self, algorithms, is_high_entropy=False, file_path=None):
        if is_high_entropy and not algorithms:
            extension = os.path.splitext(file_path)[1].lower() if file_path else ""
            header = self.get_file_header(file_path) if file_path else "unknown"
            if extension in [".gz", ".zip"]:
                return "Compressed file detected; no quantum-resistant migration needed unless encryption is also used"
            elif extension in [".pem", ".key", ".crt"]:
                return "Likely cryptographic key or certificate; migrate to quantum-resistant algorithms like CRYSTALS-Kyber or CRYSTALS-Dilithium"
            elif header == "openssl":
                return "OpenSSL-encrypted file detected; migrate to quantum-resistant algorithms like AES-256 or CRYSTALS-Kyber"
            else:
                return "High-entropy file, possibly encrypted; consider migrating to quantum-resistant algorithms like AES-256 or CRYSTALS-Kyber"
        if not algorithms:
            return "No quantum-vulnerable algorithms detected"
        recommendations = []
        for algo in algorithms:
            if is_quantum_vulnerable(algo):
                pqc_alt = get_pqc_alternative(algo)
                if pqc_alt and pqc_alt != "Unknown":
                    recommendations.append(pqc_alt)
        return "; ".join(recommendations) if recommendations else "No quantum-vulnerable algorithms detected"