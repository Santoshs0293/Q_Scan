import requests
from requests.exceptions import SSLError, RequestException
import nmap
import ssl
import socket
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from flask import Flask, request, jsonify
import urllib3
from utils.crypto_db import is_quantum_vulnerable, get_pqc_alternative, get_security_level, get_severity, ALGORITHMS
from utils.helpers import setup_logger, calculate_entropy

class WebScanner:
    def __init__(self, target, login=None):
        self.target = target
        self.login = login
        self.logger = setup_logger("WebScanner")
        self.nm = nmap.PortScanner()
        self.app = Flask(__name__)
        self.setup_routes()

    def setup_routes(self):
        @self.app.route('/scan/blackbox', methods=['POST'])
        def scan_blackbox():
            data = request.json
            target = data.get('target', self.target)
            results = self.scan()
            return jsonify(results)

    def scan(self):
        self.logger.info(f"Performing blackbox scan on {self.target}")
        results = {"items": [], "skipped_items": []}
        
        # Helper to check if port is open
        def is_port_open(host, port):
            sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            try:
                result = sock.connect_ex((host, port))
                return result == 0
            except socket.gaierror:
                results["skipped_items"].append(f"{host}:{port}: Unable to resolve host")
                self.logger.warning(f"Unable to resolve host {host}:{port}")
                return False
            except Exception as e:
                results["skipped_items"].append(f"{host}:{port}: Connection error - {str(e).split('(')[0].strip()}")
                self.logger.warning(f"Connection error for {host}:{port}: {e}")
                return False
            finally:
                sock.close()
        
        # Use the cleaned target (hostname only)
        hostname = self.target  # Already cleaned by main.py (e.g., 'localhost')
        try:
            socket.inet_pton(socket.AF_INET6, hostname)
            target_ip = hostname
        except socket.error:
            target_ip = "127.0.0.1" if hostname == "localhost" else hostname
        
        # HTTP scan
        if is_port_open(target_ip, 80):
            try:
                response = requests.get(f"http://{hostname}", timeout=5, verify=False)
                results["items"].append({
                    "id": "http",
                    "type": "protocol",
                    "algorithms": [],
                    "analysis": {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "entropy": None,
                        "protocol": "HTTP",
                        "metadata": {"url": f"http://{hostname}"},
                        "encryption_markers": None,
                        "heuristics": "HTTP protocol accessible, no encryption"
                    },
                    "pqc_recommendation": "Severity: High; Migrate to HTTPS with quantum-resistant TLS ciphers (e.g., AES-256, CRYSTALS-Kyber)"
                })
            except RequestException as e:
                results["skipped_items"].append(f"http://{hostname}:80: Connection error - {str(e).split('(')[0].strip()}")
                self.logger.warning(f"HTTP scan failed: {e}")
        else:
            results["skipped_items"].append(f"http://{hostname}:80: Port 80 closed")
            self.logger.warning(f"Port 80 closed on {hostname}, skipping HTTP scan")

        # HTTPS/TLS scan
        tls_versions = []
        if hasattr(ssl, 'PROTOCOL_SSLv3'):
            tls_versions.append(("SSLv3", ssl.PROTOCOL_SSLv3))
        if hasattr(ssl, 'PROTOCOL_TLSv1'):
            tls_versions.append(("TLSv1.0", ssl.PROTOCOL_TLSv1))
        if hasattr(ssl, 'PROTOCOL_TLSv1_1'):
            tls_versions.append(("TLSv1.1", ssl.PROTOCOL_TLSv1_1))
        if hasattr(ssl, 'PROTOCOL_TLSv1_2'):
            tls_versions.append(("TLSv1.2", ssl.PROTOCOL_TLSv1_2))
        if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
            tls_versions.append(("TLSv1.3", ssl.PROTOCOL_TLSv1_3))
        
        if not tls_versions:
            results["skipped_items"].append(f"https://{hostname}:443: No SSL/TLS protocols supported by this Python version")
            self.logger.error("No SSL/TLS protocols supported by this Python version")
        elif is_port_open(target_ip, 443):
            cert, cipher = self.get_tls_certificate(hostname, 443)
            for tls_name, tls_protocol in tls_versions:
                try:
                    context = ssl.SSLContext(tls_protocol)
                    context.verify_mode = ssl.CERT_NONE  # Disable verify for localhost testing
                    http = urllib3.PoolManager(ssl_context=context)
                    response = http.request('GET', f"https://{hostname}", timeout=5)
                    algorithms = self.analyze_tls(response, cert, cipher)
                    analysis = {
                        "status_code": response.status,
                        "headers": dict(response.headers),
                        "entropy": calculate_entropy(cert.encode()) if cert else None,
                        "protocol": "HTTPS",
                        "tls_version": tls_name,
                        "metadata": self.get_cert_metadata(cert) if cert else {"port": 443},
                        "encryption_markers": "TLS certificate detected" if cert else "TLS ciphers detected",
                        "heuristics": f"TLS-enabled service; version: {tls_name}"
                    }
                    results["items"].append({
                        "id": "https_443_tcp",
                        "type": "protocol",
                        "algorithms": algorithms,
                        "analysis": analysis,
                        "pqc_recommendation": self.get_pqc_recommendation(algorithms, is_tls=True)
                    })
                    break
                except SSLError as ssl_err:
                    if tls_name == tls_versions[-1][0]:
                        try:
                            context = ssl.create_default_context()
                            context.verify_mode = ssl.CERT_NONE
                            http = urllib3.PoolManager(ssl_context=context)
                            response = http.request('GET', f"https://{hostname}", timeout=5)
                            algorithms = self.analyze_tls(response, cert, cipher)
                            analysis = {
                                "status_code": response.status,
                                "headers": dict(response.headers),
                                "entropy": calculate_entropy(cert.encode()) if cert else None,
                                "protocol": "HTTPS",
                                "tls_version": "default",
                                "metadata": self.get_cert_metadata(cert) if cert else {"port": 443},
                                "encryption_markers": "TLS certificate detected" if cert else "TLS ciphers detected",
                                "heuristics": "TLS-enabled service; default TLS version"
                            }
                            results["items"].append({
                                "id": "https_443_tcp",
                                "type": "protocol",
                                "algorithms": algorithms,
                                "analysis": analysis,
                                "pqc_recommendation": self.get_pqc_recommendation(algorithms, is_tls=True)
                            })
                        except (SSLError, urllib3.exceptions.RequestError) as e:
                            results["skipped_items"].append(f"https://{hostname}:443: SSL error - {str(e).split('(')[0].strip()}")
                            self.logger.warning(f"HTTPS scan failed: {e}")
                    continue
                except urllib3.exceptions.RequestError as e:
                    results["skipped_items"].append(f"https://{hostname}:443: Connection error - {str(e).split('(')[0].strip()}")
                    self.logger.warning(f"HTTPS connection error: {e}")
                    break
        else:
            results["skipped_items"].append(f"https://{hostname}:443: Port 443 closed")
            self.logger.warning(f"Port 443 closed on {hostname}, skipping HTTPS scan")

        # Port scanning with SSH and TLS analysis
        try:
            self.nm.scan(hostname, arguments="-p 1-65535 -sV --script ssl-enum-ciphers,ssh2-enum-algos")
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    for port in self.nm[host][proto].keys():
                        if port in [80, 443]:
                            continue
                        service = self.nm[host][proto][port]
                        algorithms = []
                        analysis = {
                            "entropy": None,
                            "service": service['name'],
                            "product": service.get('product', 'unknown'),
                            "version": service.get('version', 'unknown'),
                            "metadata": {"port": port, "protocol": proto},
                            "encryption_markers": None,
                            "heuristics": f"Open port: {service['name']}"
                        }
                        if service['name'] == 'ssh' and 'script' in service and 'ssh2-enum-algos' in service['script']:
                            algorithms = self.analyze_ssh(service['script']['ssh2-enum-algos'])
                            analysis["encryption_markers"] = "SSH ciphers detected"
                            analysis["heuristics"] = "SSH service with cryptographic algorithms"
                        elif 'script' in service and 'ssl-enum-ciphers' in service['script']:
                            algorithms = self.analyze_nmap_tls(service['script']['ssl-enum-ciphers'])
                            analysis["encryption_markers"] = "TLS ciphers detected"
                            analysis["heuristics"] = "TLS-enabled service"
                        results["items"].append({
                            "id": f"port_{port}_{proto}",
                            "type": "port",
                            "algorithms": algorithms,
                            "analysis": analysis,
                            "pqc_recommendation": self.get_pqc_recommendation(algorithms, is_service=True)
                        })
        except Exception as e:
            results["skipped_items"].append(f"Port scan: {str(e).split('(')[0].strip()}")
            self.logger.warning(f"Port scan failed: {e}")

        return results

    def get_tls_certificate(self, hostname, port):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(True)
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    cert_pem = cert.public_bytes(encoding=x509.Encoding.PEM).decode('utf-8')
                    cipher = ssock.cipher()
                    return cert_pem, cipher
        except Exception as e:
            self.logger.warning(f"Failed to retrieve TLS certificate for {hostname}:{port}: {e}")
            return None, None

    def get_cert_metadata(self, cert):
        if not cert:
            return {}
        try:
            cert_obj = x509.load_pem_x509_certificate(cert.encode(), default_backend())
            return {
                "issuer": str(cert_obj.issuer),
                "subject": str(cert_obj.subject),
                "not_before": cert_obj.not_valid_before.isoformat(),
                "not_after": cert_obj.not_valid_after.isoformat()
            }
        except Exception as e:
            self.logger.warning(f"Failed to parse certificate metadata: {e}")
            return {}

    def analyze_tls(self, response, cert, cipher):
        algorithms = []
        if cert:
            try:
                cert_obj = x509.load_pem_x509_certificate(cert.encode(), default_backend())
                pubkey = cert_obj.public_key()
                if isinstance(pubkey, rsa.RSAPublicKey):
                    bits = pubkey.key_size
                    algorithms.append({"base": "RSA", "bits": bits, "full": f"RSA-{bits}"})
                elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                    bits = pubkey.curve.key_size
                    algorithms.append({"base": "ECDSA", "bits": bits, "full": f"ECDSA-{bits}"})
            except Exception as e:
                self.logger.warning(f"Failed to analyze TLS certificate: {e}")
        if cipher:
            name, version, bits = cipher
            parts = name.split('-')
            for p in parts:
                for base in ALGORITHMS.keys():
                    match = re.match(fr"{re.escape(base)}(\d*)", p, re.I)
                    if match:
                        p_bits = int(match.group(1)) if match.group(1) else bits
                        full = f"{base}-{p_bits}" if p_bits else base
                        algorithms.append({"base": base, "bits": p_bits, "full": full})
        # Deduplicate
        unique = {a['full']: a for a in algorithms}.values()
        return list(unique)

    def analyze_ssh(self, ssh_output):
        return self.detect_algorithms(ssh_output)

    def analyze_nmap_tls(self, tls_output):
        return self.detect_algorithms(tls_output)

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

    def get_pqc_recommendation(self, algorithms, is_tls=False, is_service=False):
        if is_tls and not algorithms:
            return "Severity: High; Use quantum-resistant TLS ciphers (e.g., AES-256, CRYSTALS-Kyber)"
        if is_service and not algorithms:
            return "Severity: Medium; Ensure service uses quantum-resistant algorithms (e.g., AES-256, CRYSTALS-Kyber)"
        if not algorithms:
            return "Severity: Low; No quantum-vulnerable algorithms detected"
        recommendations = []
        for a in algorithms:
            base = a['base']
            bits = a['bits']
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

    def run(self):
        self.app.run(debug=False)