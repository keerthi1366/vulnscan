import json
import tempfile
import unittest
from pathlib import Path

from vulnscan.models import Assessment, Observation, Software
from vulnscan.report import write_reports


class ReportTests(unittest.TestCase):
    def test_writes_json_and_csv(self):
        with tempfile.TemporaryDirectory() as directory:
            assessment = Assessment("2026-01-01T00:00:00+00:00", "host", "Linux",
                                    software=[Software("demo", "1.0", "test")],
                                    observations=[Observation("firewall", "unknown", "Unavailable", "n/a")])
            json_path, csv_path = write_reports(assessment, Path(directory), "test")
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["hostname"], "host")
            self.assertIn("firewall", csv_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
