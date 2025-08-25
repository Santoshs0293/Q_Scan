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