"""JSON and CSV report writers."""

import csv
import json
from pathlib import Path

from .models import Assessment


def write_reports(assessment: Assessment, output_dir: Path, stamp: str) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"vulnscan-{stamp}.json"
    csv_path = output_dir / f"vulnscan-{stamp}.csv"
    json_path.write_text(json.dumps(assessment.to_dict(), indent=2), encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        fields = ["record_type", "name", "status", "version", "cvss_version", "cvss_source", "cvss_score", "severity", "summary", "evidence", "source_url", "remediation"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for software in assessment.software:
            writer.writerow({"record_type": "software", "name": software.name, "version": software.version or "", "evidence": software.source})
        for observation in assessment.observations:
            writer.writerow({"record_type": "observation", "name": observation.check, "status": observation.status,
                             "summary": observation.summary, "evidence": observation.evidence,
                             "remediation": observation.remediation or ""})
        for finding in assessment.findings:
            writer.writerow({"record_type": "cve", "name": finding.cve_id, "status": finding.match_status,
                             "version": finding.installed_version, "cvss_version": finding.cvss_version or "",
                             "cvss_source": finding.cvss_source or "",
                             "cvss_score": finding.cvss_score if finding.cvss_score is not None else "",
                             "severity": finding.severity or "",
                             "summary": finding.summary, "evidence": finding.evidence,
                             "source_url": finding.source_url, "remediation": finding.remediation or ""})
        for limitation in assessment.limitations:
            writer.writerow({"record_type": "limitation", "summary": limitation})
    return json_path, csv_path
