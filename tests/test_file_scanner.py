import unittest
from scanner.file_scanner import FileScanner

class TestFileScanner(unittest.TestCase):
    def test_complete_scan(self):
        scanner = FileScanner("localhost")
        results = scanner.scan()
        self.assertIn("vulnerabilities", results)
        self.assertIn("crypto_algorithms", results)

if __name__ == "__main__":
    unittest.main()