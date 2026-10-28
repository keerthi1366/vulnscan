import unittest
import json
from io import BytesIO
from urllib.parse import parse_qs, urlparse

from vulnscan.models import Software
from vulnscan.nvd import fetch_cve_page, findings_for_product, product_cpe, scan_inventory


SAMPLE = {
    "vulnerabilities": [{"cve": {
        "id": "CVE-2099-12345",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "A sample issue for testing."}],
        "metrics": {"cvssMetricV31": [{"source": "test-authority", "cvssData": {"version": "3.1", "baseScore": 8.1, "baseSeverity": "HIGH"}}]},
        "references": [{"url": "https://vendor.example/security/advisory"}],
        "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{
            "vulnerable": True,
            "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "120.0",
        }]}]}],
    }}]
}


class NvdTests(unittest.TestCase):
    def test_api_paginates_until_all_results_are_collected(self):
        requested_offsets = []

        def opener(request, timeout):
            offset = int(parse_qs(urlparse(request.full_url).query)["startIndex"][0])
            requested_offsets.append(offset)
            rows = [{"id": str(index)} for index in range(offset, min(offset + 2, 3))]
            return BytesIO(json.dumps({"totalResults": 3, "vulnerabilities": rows}).encode("utf-8"))

        waits = []
        payload = fetch_cve_page("cpe:2.3:a:microsoft:edge_chromium:1.0:*:*:*:*:*:*:*",
                                 opener=opener, sleeper=waits.append)
        self.assertEqual(requested_offsets, [0, 2])
        self.assertEqual(len(payload["vulnerabilities"]), 3)
        self.assertEqual(waits, [6.0])

    def test_explicit_product_mapping(self):
        self.assertEqual(product_cpe(Software("Google Chrome", "119.0", "test")),
                         "cpe:2.3:a:google:chrome:119.0:*:*:*:*:*:*:*")
        self.assertIsNone(product_cpe(Software("Mystery App", "1.0", "test")))
        self.assertIsNone(product_cpe(Software("Python Launcher", "3.13.15150.0", "test")))
        self.assertEqual(product_cpe(Software("Python 3.13.15 (64-bit)", "3.13.15", "test")),
                         "cpe:2.3:a:python:python:3.13.15:*:*:*:*:*:*:*")
        self.assertEqual(product_cpe(Software("Microsoft Edge", "156.0.4314.50", "test")),
                         "cpe:2.3:a:microsoft:edge_chromium:156.0.4314.50:*:*:*:*:*:*:*")
        self.assertEqual(product_cpe(Software("Microsoft Visual Studio Code (User)", "1.143.1", "test")),
                         "cpe:2.3:a:microsoft:visual_studio_code:1.143.1:*:*:*:*:*:*:*")
        self.assertEqual(product_cpe(Software("MySQL Server 8.0", "8.0.46", "test")),
                         "cpe:2.3:a:oracle:mysql_server:8.0.46:*:*:*:*:*:*:*")
        self.assertEqual(product_cpe(Software("Oracle VirtualBox 7.2.20", "7.2.20", "test")),
                         "cpe:2.3:a:oracle:vm_virtualbox:7.2.20:*:*:*:*:*:*:*")
        self.assertEqual(product_cpe(Software("Microsoft .NET Runtime - 8.0.22 (x64)", "8.0.22", "test")),
                         "cpe:2.3:a:microsoft:.net:8.0.22:*:*:*:*:*:*:*")
        self.assertEqual(product_cpe(Software("MySQL Workbench 8.0 CE", "8.0.47", "test")),
                         "cpe:2.3:a:oracle:mysql_workbench:8.0.47:*:*:*:*:*:*:*")
        self.assertEqual(product_cpe(Software("MySQL Shell", "8.0.46", "test")),
                         "cpe:2.3:a:oracle:mysql_shell:8.0.46:*:*:*:*:*:*:*")

    def test_cve_payload_becomes_evidence_backed_potential_match(self):
        software = Software("Google Chrome", "119.0", "test inventory")
        cpe = product_cpe(software)
        rows = findings_for_product(software, SAMPLE, cpe)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].match_status, "potential_match")
        self.assertEqual(rows[0].severity, "HIGH")
        self.assertEqual(rows[0].cvss_source, "test-authority")
        self.assertIn("versionEndExcluding", rows[0].evidence)

    def test_complex_and_configuration_is_uncertain(self):
        payload = {"vulnerabilities": [{"cve": {
            "id": "CVE-2099-98765", "descriptions": [], "metrics": {},
            "configurations": [{"nodes": [{"operator": "AND", "cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                "versionEndExcluding": "120.0",
            }]}]}],
        }}]}
        software = Software("Google Chrome", "119.0", "test")
        rows = findings_for_product(software, payload, product_cpe(software))
        self.assertEqual(rows[0].match_status, "uncertain")

    def test_scan_uses_injected_fetcher_without_network(self):
        calls = []
        rows, limitations = scan_inventory(
            [Software("Google Chrome", "119.0", "test"), Software("Mystery App", "1.0", "test")],
            fetcher=lambda cpe, key: calls.append((cpe, key)) or SAMPLE,
            sleeper=lambda seconds: self.fail("only one product should not wait"),
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(calls), 1)
        self.assertTrue(any("NVD matches indicate" in note for note in limitations))
        self.assertTrue(any("were skipped" in note for note in limitations))

    def test_cross_minor_range_is_uncertain_for_maintained_release_branches(self):
        payload = {"vulnerabilities": [{"cve": {
            "id": "CVE-2099-98766", "descriptions": [], "metrics": {},
            "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*",
                "versionEndIncluding": "3.14.4",
            }]}]}],
        }}]}
        software = Software("Python 3.13.15 (64-bit)", "3.13.15", "test")
        rows = findings_for_product(software, payload, product_cpe(software))
        self.assertEqual(rows[0].match_status, "uncertain")

    def test_mysql_cross_minor_range_is_uncertain(self):
        payload = {"vulnerabilities": [{"cve": {
            "id": "CVE-2099-98767", "descriptions": [], "metrics": {},
            "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:oracle:mysql_server:*:*:*:*:*:*:*:*",
                "versionEndIncluding": "8.4.0",
            }]}]}],
        }}]}
        software = Software("MySQL Server 8.0", "8.0.46", "test")
        rows = findings_for_product(software, payload, product_cpe(software))
        self.assertEqual(rows[0].match_status, "uncertain")

    def test_repeated_components_with_same_cpe_are_queried_once(self):
        calls = []
        software = [Software("Python 3.13.15", "3.13.15", "test"),
                    Software("Python 3.13.15 Core Interpreter", "3.13.15", "test")]
        scan_inventory(software, fetcher=lambda cpe, key: calls.append(cpe) or {"vulnerabilities": []},
                       sleeper=lambda _: self.fail("duplicate CPEs should result in one request"))
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
