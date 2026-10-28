"""CLI entry point."""

import argparse
from datetime import datetime, timezone
from pathlib import Path
import platform
import socket

from .checks import collect_observations
from .inventory import installed_software, operating_system
from .models import Assessment
from .nvd import configured_api_key, scan_inventory
from .report import write_reports


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only local security assessment starter")
    parser.add_argument("--out", type=Path, default=Path("reports"), help="report output directory")
    parser.add_argument("--nvd", action="store_true", help="look up mapped software in NIST NVD (makes network requests)")
    args = parser.parse_args()
    now = datetime.now(timezone.utc)
    software, limitations = installed_software()
    findings = []
    if args.nvd:
        print("NVD lookup enabled for explicitly mapped products; requests are read-only and paced.")
        findings, nvd_limitations = scan_inventory(software, configured_api_key())
        limitations.extend(nvd_limitations)
    assessment = Assessment(
        assessed_at=now.isoformat(), hostname=socket.gethostname(), operating_system=operating_system(),
        software=software, observations=collect_observations(), findings=findings, limitations=limitations + ([
            "NVD lookups were not enabled; no CVE conclusions were generated.",
        ] if not args.nvd else []) + [
            "Inventory and configuration checks are partial and may require elevated read permissions on some systems.",
        ],
    )
    json_path, csv_path = write_reports(assessment, args.out, now.strftime("%Y%m%dT%H%M%SZ"))
    potential_count = sum(item.match_status == "potential_match" for item in findings)
    uncertain_count = sum(item.match_status == "uncertain" for item in findings)
    print(f"Host: {assessment.hostname} ({platform.system()})")
    print(f"Software entries: {len(software)}; observations: {len(assessment.observations)}; "
          f"CVE results: {len(findings)} ({potential_count} potential matches, {uncertain_count} uncertain)")
    if not args.nvd:
        print("CVE matching was not performed; this is not a clean bill of health.")
    elif potential_count:
        print("Potential matches are prioritized by available CVSS score; review evidence and vendor guidance.")
    elif uncertain_count:
        print("Only uncertain matches were returned; verify vendor version ranges before treating them as applicable.")
    else:
        print("No potential matches returned for mapped products; unsupported products or unavailable NVD analysis remain possible.")
    print(f"JSON report: {json_path}\nCSV report:  {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
