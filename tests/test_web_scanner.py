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