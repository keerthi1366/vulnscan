"""Selected read-only security posture observations."""

import platform
import json
import re
import subprocess

from .models import Observation

WINDOWS_SERVICES = ("RemoteRegistry", "TermService", "WinRM", "Spooler")
LINUX_SERVICES = ("ssh", "sshd", "cups", "smbd")


def _command(args: list[str]) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=15, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"command exited {result.returncode}")
    return result.stdout.strip()


def collect_observations() -> list[Observation]:
    observations: list[Observation] = []
    system = platform.system()
    try:
        if system == "Windows":
            output = _command(["netsh", "advfirewall", "show", "allprofiles", "state"])
            states = [match.group(1).upper() for line in output.splitlines()
                      if (match := re.match(r"^\s*State\s*:?\s*(ON|OFF)\s*$", line, re.IGNORECASE))]
            if states:
                enabled = all(state == "ON" for state in states)
                observations.append(Observation(
                    "firewall_profiles", "pass" if enabled else "finding",
                    "All reported Windows firewall profiles are on." if enabled else "One or more Windows firewall profiles are off.",
                    "; ".join(f"State {state}" for state in states),
                    "Review Windows Defender Firewall settings for the affected profile." if not enabled else None,
                ))
            else:
                observations.append(Observation("firewall_profiles", "unknown", "Firewall state could not be parsed.", output[:500]))
        elif system == "Linux":
            try:
                output = _command(["ufw", "status", "verbose"])
                active = output.lower().startswith("status: active")
                observations.append(Observation(
                    "ufw_firewall", "pass" if active else "info",
                    "UFW reports active." if active else "UFW is not active; another firewall may be in use.", output[:1000]
                ))
            except (FileNotFoundError, RuntimeError, subprocess.TimeoutExpired) as exc:
                observations.append(Observation("ufw_firewall", "unknown", "UFW status is unavailable; another firewall may be in use.", str(exc)))
        else:
            observations.append(Observation("firewall", "unknown", f"Firewall check is not implemented for {system}.", ""))
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        observations.append(Observation("firewall", "unknown", "Firewall state could not be collected.", str(exc)))

    observations.extend(collect_service_observations(system))
    return observations


def collect_service_observations(system: str | None = None) -> list[Observation]:
    """Inspect a small local service allowlist; never change service state."""
    system = system or platform.system()
    observations: list[Observation] = []
    if system == "Windows":
        names = ",".join(f"'{name}'" for name in WINDOWS_SERVICES)
        script = (
            f"$names=@({names}); Get-CimInstance Win32_Service | "
            "Where-Object { $_.Name -in $names } | "
            "Select-Object Name,State,StartMode | ConvertTo-Json -Compress"
        )
        try:
            raw = _command(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script])
            rows = json.loads(raw) if raw else []
            if isinstance(rows, dict):
                rows = [rows]
            found = {str(row.get("Name", "")): row for row in rows if isinstance(row, dict)}
            for name in WINDOWS_SERVICES:
                row = found.get(name)
                if row is None:
                    observations.append(Observation(
                        f"service:{name}", "info", f"{name} was not found or was not visible.",
                        "Read-only Win32_Service query; absence does not imply a security issue."
                    ))
                else:
                    state = str(row.get("State", "Unknown"))
                    start_mode = str(row.get("StartMode", "Unknown"))
                    observations.append(Observation(
                        f"service:{name}", "info", f"{name} state: {state}; start mode: {start_mode}.",
                        f"Win32_Service Name={name}, State={state}, StartMode={start_mode}.",
                        "Review whether this service is needed for your use; VulnScan does not change it."
                    ))
        except (OSError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            observations.append(Observation("selected_services", "unknown", "Selected Windows service states could not be collected.", str(exc)))
        return observations
    if system == "Linux":
        for name in LINUX_SERVICES:
            try:
                raw = _command(["systemctl", "show", "--property=Id,LoadState,ActiveState,UnitFileState", f"{name}.service"])
                details = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
                if details.get("LoadState") == "not-found":
                    observations.append(Observation(
                        f"service:{name}", "info", f"{name} was not found.", "Read-only systemctl query."
                    ))
                else:
                    state = details.get("ActiveState", "unknown")
                    start_mode = details.get("UnitFileState", "unknown")
                    observations.append(Observation(
                        f"service:{name}", "info", f"{name} state: {state}; enablement: {start_mode}.", raw,
                        "Review whether this service is needed for your use; VulnScan does not change it."
                    ))
            except (FileNotFoundError, RuntimeError, subprocess.TimeoutExpired) as exc:
                observations.append(Observation(f"service:{name}", "unknown", "Service state could not be collected.", str(exc)))
        return observations
    return [Observation("selected_services", "unknown", f"Service checks are not implemented for {system}.", "")]
