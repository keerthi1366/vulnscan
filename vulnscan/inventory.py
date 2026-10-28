"""Read-only host and installed software inventory."""

import platform
import re
import subprocess
import sys

from .models import Software


def operating_system() -> str:
    return f"{platform.system()} {platform.release()} ({platform.version()})"


def normalize_installed_version(display_name: str, display_version: str | None) -> str | None:
    """Use public Python/.NET release versions instead of Windows installer IDs."""
    python_release = re.match(r"^Python\s+(\d+\.\d+\.\d+)(?:\s|$)", display_name, re.IGNORECASE)
    if python_release:
        return python_release.group(1)
    if re.match(r"^Microsoft\s+(?:\.NET\b|Windows Desktop Runtime\b)", display_name, re.IGNORECASE):
        dotnet_release = re.search(r"(?<!\d)(\d+\.\d+\.\d+)(?:\s|\(|$)", display_name)
        if dotnet_release:
            return dotnet_release.group(1)
    return display_version


def _run(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"command exited {result.returncode}")
    return result.stdout


def installed_software() -> tuple[list[Software], list[str]]:
    """Return software and collection limitations without changing the host."""
    system = platform.system()
    try:
        if system == "Windows":
            # Registry enumeration is read-only; avoids slow/unreliable Win32_Product.
            import winreg

            rows: dict[tuple[str, str], Software] = {}
            locations = (
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            )
            for hive, path in locations:
                try:
                    root = winreg.OpenKey(hive, path)
                except OSError:
                    continue
                with root:
                    for index in range(winreg.QueryInfoKey(root)[0]):
                        try:
                            child_name = winreg.EnumKey(root, index)
                            with winreg.OpenKey(root, child_name) as child:
                                name = winreg.QueryValueEx(child, "DisplayName")[0]
                                try:
                                    version = str(winreg.QueryValueEx(child, "DisplayVersion")[0])
                                except OSError:
                                    version = None
                                # Windows records a Python installer build ID rather
                                # than the public CPython release in DisplayVersion.
                                version = normalize_installed_version(str(name), version)
                                rows[(str(name).casefold(), version or "")] = Software(
                                    str(name), version, "Windows uninstall registry"
                                )
                        except OSError:
                            continue
            return sorted(rows.values(), key=lambda item: item.name.casefold()), []
        if system == "Linux":
            if sys.platform.startswith("linux"):
                try:
                    output = _run(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"])
                    source = "dpkg-query"
                except (FileNotFoundError, RuntimeError):
                    output = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
                    source = "rpm"
                packages = [Software(name, version, source) for line in output.splitlines()
                            if len(parts := line.split("\t", 1)) == 2
                            for name, version in [parts] if name and version]
                return sorted(packages, key=lambda item: item.name.casefold()), []
        return [], [f"Installed software inventory is not implemented for {system}."]
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        return [], [f"Installed software could not be collected: {exc}"]
