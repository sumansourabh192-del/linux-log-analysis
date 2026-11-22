
import unittest
import tempfile
from pathlib import Path

from src.analyzer import analyze_log


class TestLogAnalysis(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = Path(self.temp_dir.name) / "test_auth.log"

        self.log_file.write_text(
            "Failed password for suman from 192.168.1.50 port 50121 ssh2\n"
            "Failed password for suman from 192.168.1.50 port 50122 ssh2\n"
            "Failed password for invalid user invaliduser from 192.168.1.50 port 50123 ssh2\n"
            "Accepted password for suman from 192.168.1.10 port 50124 ssh2\n"
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_failed_login_count(self):
        results = analyze_log(self.log_file, 3)

        self.assertEqual(
            results["failed_attempts"]["192.168.1.50"],
            3
        )

    def test_successful_login_count(self):
        results = analyze_log(self.log_file, 3)

        self.assertEqual(
            results["successful_attempts"]["192.168.1.10"],
            1
        )

    def test_failed_username_count(self):
        results = analyze_log(self.log_file, 3)

        self.assertEqual(
            results["failed_usernames"]["suman"],
            2
        )

    def test_suspicious_ip_detection(self):
        results = analyze_log(self.log_file, 3)

        self.assertGreaterEqual(
            results["failed_attempts"]["192.168.1.50"],
            results["threshold"]
        )


if __name__ == "__main__":
    unittest.main()
