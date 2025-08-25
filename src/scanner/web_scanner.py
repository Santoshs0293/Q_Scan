# web_scanner.py
import requests
from requests.exceptions import SSLError, RequestException
import nmap
import ssl
import socket
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from flask import Flask, request, jsonify
import urllib3
from utils.crypto_db import is_quantum_vulnerable, get_pqc_alternative, CLASSICAL_ALGORITHMS
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
                    "pqc_recommendation": "Migrate to HTTPS with quantum-resistant TLS ciphers (e.g., AES-256, CRYSTALS-Kyber)"
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
            cert = self.get_tls_certificate(hostname, 443)
            for tls_name, tls_protocol in tls_versions:
                try:
                    context = ssl.SSLContext(tls_protocol)
                    context.verify_mode = ssl.CERT_NONE  # Disable verify for localhost testing
                    http = urllib3.PoolManager(ssl_context=context)
                    response = http.request('GET', f"https://{hostname}", timeout=5)
                    algorithms = self.analyze_tls(response, cert)
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
                            algorithms = self.analyze_tls(response, cert)
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
                    return cert.public_bytes(encoding=x509.Encoding.PEM).decode('utf-8')
        except Exception as e:
            self.logger.warning(f"Failed to retrieve TLS certificate for {hostname}:{port}: {e}")
            return None

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

    def analyze_tls(self, response, cert):
        algorithms = []
        if cert:
            try:
                cert_obj = x509.load_pem_x509_certificate(cert.encode(), default_backend())
                pubkey = cert_obj.public_key()
                algo_name = pubkey.__class__.__name__
                algo_map = {
                    "RSAPublicKey": "RSA",
                    "EllipticCurvePublicKey": "ECDSA",
                }
                mapped_algo = algo_map.get(algo_name)
                if mapped_algo and mapped_algo in CLASSICAL_ALGORITHMS:
                    algorithms.append(mapped_algo)
            except Exception as e:
                self.logger.warning(f"Failed to analyze TLS certificate: {e}")
        try:
            cipher = response.headers.get('cipher', '').lower()
            for algo in CLASSICAL_ALGORITHMS.keys():
                if algo.lower() in cipher and algo not in algorithms:
                    algorithms.append(algo)
        except Exception:
            pass
        return algorithms

    def analyze_ssh(self, ssh_output):
        algorithms = []
        for algo in CLASSICAL_ALGORITHMS.keys():
            pattern = fr"\b{re.escape(algo)}\b"
            if re.search(pattern, ssh_output, re.IGNORECASE) and algo not in algorithms:
                algorithms.append(algo)
        return algorithms

    def analyze_nmap_tls(self, tls_output):
        algorithms = []
        for algo in CLASSICAL_ALGORITHMS.keys():
            pattern = fr"\b{re.escape(algo)}\b"
            if re.search(pattern, tls_output, re.IGNORECASE) and algo not in algorithms:
                algorithms.append(algo)
        return algorithms

    def get_pqc_recommendation(self, algorithms, is_tls=False, is_service=False):
        if is_tls and not algorithms:
            return "Use quantum-resistant TLS ciphers (e.g., AES-256, CRYSTALS-Kyber)"
        if is_service and not algorithms:
            return "Ensure service uses quantum-resistant algorithms (e.g., AES-256, CRYSTALS-Kyber)"
        if not algorithms:
            return "No quantum-vulnerable algorithms detected"
        recommendations = []
        for algo in algorithms:
            if is_quantum_vulnerable(algo):
                pqc_alt = get_pqc_alternative(algo)
                if pqc_alt and pqc_alt != "Unknown":
                    recommendations.append(pqc_alt)
        return "; ".join(recommendations) if recommendations else "No quantum-vulnerable algorithms detected"

    def run(self):
        self.app.run(debug=False)