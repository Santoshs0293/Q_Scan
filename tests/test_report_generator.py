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