"""Small, opt-in client for NIST NVD CVE API 2.0."""

import json
import os
import re
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen

from .matching import VersionRange, cpe_vendor_product, match_version, nvd_range
from .models import Finding, Software

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_URL = "https://nvd.nist.gov/vuln/detail/"

# Only exact inventory display names or explicit versioned families are mapped.
# This list is intentionally small; unsupported names are skipped, not guessed.
PRODUCTS: dict[str, tuple[str, str]] = {
    "7-zip": ("7-zip", "7-zip"),
    "microsoft edge": ("microsoft", "edge_chromium"),
    "google chrome": ("google", "chrome"),
    "mozilla firefox": ("mozilla", "firefox"),
    "vlc media player": ("videolan", "vlc"),
    "git": ("git-scm", "git"),
    "node.js": ("nodejs", "node.js"),
    "microsoft visual studio code (user)": ("microsoft", "visual_studio_code"),
}


def product_cpe(software: Software) -> str | None:
    if not software.version:
        return None
    name = software.name.casefold().strip()
    mapping = PRODUCTS.get(name)
    if mapping is None and (name.startswith("microsoft .net ") or name.startswith("microsoft windows desktop runtime")):
        mapping = ("microsoft", ".net")
    if mapping is None and re.match(r"^python\s+\d+\.\d+", name):
        mapping = ("python", "python")
    if mapping is None and re.match(r"^mysql server\s+\d", name):
        mapping = ("oracle", "mysql_server")
    if mapping is None and name.startswith("mysql workbench "):
        mapping = ("oracle", "mysql_workbench")
    if mapping is None and name.startswith("mysql shell"):
        mapping = ("oracle", "mysql_shell")
    if mapping is None and re.match(r"^oracle virtualbox\s+\d", name):
        mapping = ("oracle", "vm_virtualbox")
    if mapping is None:
        return None
    vendor, product = mapping
    # Escape CPE formatted-string reserved characters. URL encoding is applied
    # separately by urlencode when the complete CPE is sent to the API.
    version = re.sub(r"([\\:*?!\"#$%&'()+,/<=>@\[\]^`{|}~ ])", r"\\\1", software.version.strip())
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def fetch_cve_page(cpe: str, api_key: str | None = None,
                   opener: Callable[..., Any] = urlopen,
                   sleeper: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    headers = {"User-Agent": "VulnScan/0.1 (local read-only assessment)"}
    if api_key:
        headers["apiKey"] = api_key
    all_vulnerabilities: list[dict[str, Any]] = []
    start_index = 0
    total_results = 0
    while True:
        query = urlencode({"cpeName": cpe, "resultsPerPage": 2000, "startIndex": start_index})
        request = Request(f"{API_URL}?{query}", headers=headers)
        try:
            with opener(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise RuntimeError(f"NVD returned HTTP {exc.code}; retry later or check API limits.") from exc
        except (URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            raise RuntimeError(f"NVD request failed: {exc}") from exc
        page = payload.get("vulnerabilities", [])
        all_vulnerabilities.extend(page)
        total_results = int(payload.get("totalResults", len(all_vulnerabilities)))
        if not page and len(all_vulnerabilities) < total_results:
            raise RuntimeError("NVD returned an incomplete paginated response; results may be missing.")
        if not page or len(all_vulnerabilities) >= total_results:
            payload["vulnerabilities"] = all_vulnerabilities
            return payload
        start_index += len(page)
        sleeper(6.0)


def _iter_match_criteria(configurations: list[dict[str, Any]]):
    """Yield criteria and flag complex Boolean context as uncertain."""
    def visit(node: dict[str, Any], complex_context: bool = False):
        operator = str(node.get("operator", "OR")).upper()
        context = complex_context or operator == "AND" or bool(node.get("negate"))
        for item in node.get("cpeMatch", []):
            yield item, context
        for child in node.get("nodes", []):
            yield from visit(child, context)

    for configuration in configurations:
        for node in configuration.get("nodes", []):
            yield from visit(node)


def findings_for_product(software: Software, payload: dict[str, Any], cpe: str) -> list[Finding]:
    expected = cpe_vendor_product(cpe)
    if expected is None or not software.version:
        return []
    findings: list[Finding] = []
    for wrapper in payload.get("vulnerabilities", []):
        cve = wrapper.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id or str(cve.get("vulnStatus", "")).casefold() == "rejected":
            continue
        matched: list[tuple[dict[str, Any], bool]] = []
        for criterion, complex_context in _iter_match_criteria(cve.get("configurations", [])):
            if criterion.get("vulnerable") is not True:
                continue
            if cpe_vendor_product(criterion.get("criteria", "")) != expected:
                continue
            version_range = nvd_range(criterion)
            if version_range is None:
                matched.append((criterion, True))
                continue
            status = match_version(software.version, version_range)
            if status == "potential_match":
                matched.append((criterion, complex_context))
            elif status == "uncertain":
                matched.append((criterion, True))
        if not matched:
            continue
        criterion, uncertain = matched[0]
        version_range = nvd_range(criterion)
        if version_range is None:
            bounds = "NVD criterion has no supported explicit version bound"
        else:
            lower = (">=" if version_range.start.inclusive else ">") + version_range.start.value if version_range.start else "no lower bound"
            upper = ("<=" if version_range.end.inclusive else "<") + version_range.end.value if version_range.end else "no upper bound"
            bounds = f"NVD CPE version range: {lower}, {upper}"
        # Same-major/minor-line boundaries can span separately maintained
        # product branches. Without an explicit lower bound, a broad CPE range
        # alone is insufficient to claim that this branch is affected.
        if version_range and version_range.end and version_range.start is None:
            installed_parts = software.version.split(".")
            end_parts = version_range.end.value.split(".")
            if (len(installed_parts) >= 2 and len(end_parts) >= 2
                    and installed_parts[0] == end_parts[0] and installed_parts[1] != end_parts[1]):
                uncertain = True
                bounds += "; NVD range crosses minor release branches; verify the product vendor advisory for this release line"
        if uncertain:
            status = "uncertain"
            bounds += "; complex configuration or unsupported version semantics require manual review"
        else:
            status = "potential_match"
        descriptions = cve.get("descriptions", [])
        summary = next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "No English description supplied by NVD.")
        cvss_version = None
        cvss_source = None
        cvss_score = None
        severity = None
        metrics = cve.get("metrics", {})
        for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(metric_key, [])
            if entries:
                data = entries[0].get("cvssData", {})
                cvss_version = data.get("version")
                cvss_source = entries[0].get("source")
                cvss_score = data.get("baseScore")
                severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
                break
        references = cve.get("references", [])
        vendor_links = [ref.get("url") for ref in references if ref.get("url")]
        if status == "uncertain":
            remediation = "Verify applicability against the vendor's release-specific advisory before deciding on remediation; VulnScan does not change software."
        else:
            remediation = "Review the linked vendor advisory for a supported update; VulnScan does not change software."
        nvd_bound_fields = ", ".join(
            f"{key}={criterion[key]}" for key in
            ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")
            if criterion.get(key)
        ) or f"criteria={criterion.get('criteria', 'unknown')}"
        evidence = (f"Installed inventory: {software.name} {software.version}; CPE queried: {cpe}; "
                    f"NVD criterion: {criterion.get('criteria', 'unknown')}; {nvd_bound_fields}; {bounds}. "
                    f"NVD CVE record: {NVD_URL}{cve_id}.")
        if vendor_links:
            evidence += " Reference: " + vendor_links[0]
        findings.append(Finding(
            cve_id=cve_id, product=software.name, installed_version=software.version,
            match_status=status, cvss_version=cvss_version, cvss_source=cvss_source, cvss_score=cvss_score,
            severity=severity, summary=summary, source_url=NVD_URL + cve_id,
            evidence=evidence, remediation=remediation,
        ))
    return findings


def scan_inventory(software: list[Software], api_key: str | None = None,
                   sleeper: Callable[[float], None] = time.sleep,
                   fetcher: Callable[[str, str | None], dict[str, Any]] | None = None
                   ) -> tuple[list[Finding], list[str]]:
    """Look up mapped products, pacing API calls at 6 seconds between requests."""
    fetcher = fetcher or fetch_cve_page
    findings: list[Finding] = []
    limitations: list[str] = []
    supported = [(item, product_cpe(item)) for item in software]
    unmapped = sorted({f"{item.name} {item.version or '(version unavailable)'}" for item, cpe in supported if cpe is None})
    if unmapped:
        examples = ", ".join(unmapped[:8])
        suffix = ", and more" if len(unmapped) > 8 else ""
        limitations.append(
            f"{len(unmapped)} inventory entries were skipped because no verified product mapping exists "
            f"(examples: {examples}{suffix}); they were not assessed against NVD."
        )
    unique: dict[str, tuple[Software, str]] = {}
    for item, cpe in supported:
        if cpe and cpe not in unique:
            unique[cpe] = (item, cpe)
    supported = list(unique.values())
    if not supported:
        return [], ["No installed products matched VulnScan's explicit NVD product map."]
    for index, (item, cpe) in enumerate(supported):
        if index:
            sleeper(6.0)  # Conservative spacing, including keyed requests.
        try:
            payload = fetcher(cpe, api_key)
            findings.extend(findings_for_product(item, payload, cpe))
        except RuntimeError as exc:
            limitations.append(f"NVD lookup for {item.name} was unavailable: {exc}")
    findings.sort(key=lambda row: row.cvss_score if row.cvss_score is not None else -1, reverse=True)
    if api_key is None:
        limitations.append("NVD requests used the unauthenticated public rate limit; keep scans infrequent.")
    limitations.append("NVD matches indicate potential applicability, not proof of exploitability; manually verify vendor advisories and local packaging.")
    return findings, limitations


def configured_api_key() -> str | None:
    return os.environ.get("NVD_API_KEY") or None
