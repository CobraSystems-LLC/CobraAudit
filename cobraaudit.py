#!/usr/bin/env python3
"""CobraAudit - local security posture audit utilities for PCs.

Read-only health check of the machine: file permissions, accounts, SSH
hardening, sudo rules, listening ports and startup persistence. Produces
severity-ranked findings, an overall letter grade, and optional JSON/HTML
reports. Never modifies the system.

Pure standard library; Python 3.10+. Linux/ChromeOS and Windows aware.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

APP_NAME = "CobraAudit"
STATE_DIR = Path.home() / ".cobraaudit"

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}

# Services that should rarely be reachable from other machines on a PC.
RISKY_LISTENER_PORTS = {
    21: "FTP (plaintext credentials)",
    23: "Telnet (plaintext session)",
    445: "SMB file sharing",
    3389: "RDP remote desktop",
    5900: "VNC remote desktop",
    6379: "Redis (often unauthenticated)",
    27017: "MongoDB (often unauthenticated)",
}


@dataclass
class Finding:
    check: str
    title: str
    severity: str  # critical | high | medium | low | info
    detail: str = ""
    recommendation: str = ""


@dataclass
class AuditReport:
    created: str
    hostname: str
    platform: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        penalty = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        score = self.score
        if score >= 90:
            return "A"
        if score >= 75:
            return "B"
        if score >= 60:
            return "C"
        if score >= 40:
            return "D"
        return "F"

    def counts(self) -> dict[str, int]:
        return {sev: sum(1 for f in self.findings if f.severity == sev) for sev in SEVERITIES}


def _is_posix() -> bool:
    return os.name == "posix"


def _safe_stat_mode(path: Path) -> int | None:
    try:
        return path.stat().st_mode
    except OSError:
        return None


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Checks (each returns a list[Finding])
# ---------------------------------------------------------------------------

def check_sensitive_file_permissions(home: Path | None = None) -> list[Finding]:
    """Private keys and credential stores must not be readable by others."""
    if not _is_posix():
        return []
    home = home or Path.home()
    findings: list[Finding] = []

    ssh_dir = home / ".ssh"
    if ssh_dir.is_dir():
        mode = _safe_stat_mode(ssh_dir)
        if mode is not None and mode & 0o077:
            findings.append(Finding(
                check="file-permissions",
                title="~/.ssh is accessible by other users",
                severity="high",
                detail=f"{ssh_dir} has mode {oct(mode & 0o777)}",
                recommendation="Run: chmod 700 ~/.ssh",
            ))
        for key_file in sorted(ssh_dir.iterdir()):
            if key_file.name.startswith("id_") and not key_file.name.endswith(".pub"):
                key_mode = _safe_stat_mode(key_file)
                if key_mode is not None and key_mode & 0o077:
                    findings.append(Finding(
                        check="file-permissions",
                        title=f"Private key readable by others: {key_file.name}",
                        severity="critical",
                        detail=f"{key_file} has mode {oct(key_mode & 0o777)}",
                        recommendation=f"Run: chmod 600 {key_file}",
                    ))

    for cred_file, label in (
        (home / ".netrc", "netrc credential store"),
        (home / ".pgpass", "PostgreSQL password file"),
        (home / ".aws" / "credentials", "AWS credentials"),
    ):
        if cred_file.is_file():
            mode = _safe_stat_mode(cred_file)
            if mode is not None and mode & 0o077:
                findings.append(Finding(
                    check="file-permissions",
                    title=f"{label} readable by other users",
                    severity="high",
                    detail=f"{cred_file} has mode {oct(mode & 0o777)}",
                    recommendation=f"Run: chmod 600 {cred_file}",
                ))

    shadow = Path("/etc/shadow")
    if shadow.exists():
        mode = _safe_stat_mode(shadow)
        if mode is not None and mode & 0o027:
            findings.append(Finding(
                check="file-permissions",
                title="/etc/shadow readable beyond root/shadow group",
                severity="critical",
                detail=f"/etc/shadow has mode {oct(mode & 0o777)}",
                recommendation="Run: chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
            ))
    return findings


def check_world_writable(home: Path | None = None, limit: int = 25) -> list[Finding]:
    """World-writable files in your home dir let any local user tamper with them."""
    if not _is_posix():
        return []
    home = (home or Path.home()).resolve()
    findings: list[Finding] = []
    total = 0
    for current_root, directories, files in os.walk(home, onerror=lambda _: None):
        current = Path(current_root)
        directories[:] = [d for d in directories if not (current / d).is_symlink()]
        for name in directories + files:
            candidate = current / name
            if candidate.is_symlink():
                continue
            mode = _safe_stat_mode(candidate)
            if mode is not None and mode & 0o002:
                total += 1
                if len(findings) < limit:
                    findings.append(Finding(
                        check="world-writable",
                        title=f"World-writable: {candidate.relative_to(home)}",
                        severity="low",
                        detail=f"{candidate} has mode {oct(mode & 0o777)}",
                        recommendation="Remove the write bit: chmod o-w "
                        + str(candidate),
                    ))
    if total > limit:
        findings.append(Finding(
            check="world-writable",
            title=f"{total - limit} more world-writable paths not listed",
            severity="low",
            detail=f"Found {total} world-writable paths under {home} in total.",
            recommendation="Audit with: find ~ -perm -0002",
        ))
    return findings


def check_suid_sgid() -> list[Finding]:
    """Inventory SUID/SGID binaries — each is a potential privilege-escalation path."""
    if not _is_posix():
        return []
    search_dirs = [Path(d) for d in ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin")]
    suid: list[str] = []
    sgid: list[str] = []
    for base in search_dirs:
        if not base.is_dir():
            continue
        for entry in base.iterdir():
            mode = _safe_stat_mode(entry)
            if mode is None or not entry.is_file():
                continue
            if mode & 0o4000:
                suid.append(str(entry))
            elif mode & 0o2000:
                sgid.append(str(entry))
    findings: list[Finding] = []
    if suid:
        findings.append(Finding(
            check="suid-sgid",
            title=f"{len(suid)} SUID binaries installed",
            severity="info",
            detail=", ".join(sorted(suid)[:15]) + (" ..." if len(suid) > 15 else ""),
            recommendation="Compare against GTFOBins (https://gtfobins.org) — unexpected "
            "SUID binaries are a classic persistence mechanism.",
        ))
    if sgid:
        findings.append(Finding(
            check="suid-sgid",
            title=f"{len(sgid)} SGID binaries installed",
            severity="info",
            detail=", ".join(sorted(sgid)[:15]) + (" ..." if len(sgid) > 15 else ""),
            recommendation="Remove the SGID bit from binaries that do not need it.",
        ))
    return findings


def check_accounts(passwd_path: Path | None = None) -> list[Finding]:
    """Non-root UID-0 accounts and empty password fields are backdoor markers."""
    if not _is_posix():
        return []
    passwd_path = passwd_path or Path("/etc/passwd")
    content = _read_text(passwd_path)
    if content is None:
        return []
    findings: list[Finding] = []
    for line in content.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name, password_field, uid_field = parts[0], parts[1], parts[2]
        try:
            uid = int(uid_field)
        except ValueError:
            continue
        if uid == 0 and name != "root":
            findings.append(Finding(
                check="accounts",
                title=f"Non-root account with UID 0: {name}",
                severity="critical",
                detail=f"{name} has full root privileges via UID 0 in {passwd_path}",
                recommendation="Investigate immediately; legitimate systems only have root at UID 0.",
            ))
        if password_field == "":
            findings.append(Finding(
                check="accounts",
                title=f"Account with empty password: {name}",
                severity="high",
                detail=f"{name} can log in without a password.",
                recommendation=f"Lock it: sudo passwd -l {name}",
            ))
    return findings


def check_sshd_config(config_path: Path | None = None) -> list[Finding]:
    """SSH server hardening basics."""
    if not _is_posix():
        return []
    config_path = config_path or Path("/etc/ssh/sshd_config")
    content = _read_text(config_path)
    if content is None:
        return []  # sshd simply not installed — nothing to audit.

    settings: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            settings.setdefault(parts[0].lower(), parts[1].strip())

    findings: list[Finding] = []
    rules = [
        ("permitrootlogin", {"yes"}, "critical", "SSH allows direct root login",
         "Set 'PermitRootLogin no' in sshd_config."),
        ("passwordauthentication", {"yes"}, "medium", "SSH password authentication enabled",
         "Prefer key-only auth: 'PasswordAuthentication no'."),
        ("permitemptypasswords", {"yes"}, "critical", "SSH permits empty passwords",
         "Set 'PermitEmptyPasswords no'."),
        ("x11forwarding", {"yes"}, "low", "SSH X11 forwarding enabled",
         "Disable unless needed: 'X11Forwarding no'."),
    ]
    for key, bad_values, severity, title, recommendation in rules:
        if settings.get(key, "").lower() in bad_values:
            findings.append(Finding(
                check="sshd-config",
                title=title,
                severity=severity,
                detail=f"{config_path}: {key} {settings[key]}",
                recommendation=recommendation,
            ))
    return findings


def check_sudo_nopasswd(sudoers_dir: Path | None = None) -> list[Finding]:
    """NOPASSWD sudo rules defeat the point of sudo's audit trail."""
    if not _is_posix():
        return []
    candidates = [Path("/etc/sudoers")]
    sudoers_dir = sudoers_dir or Path("/etc/sudoers.d")
    if sudoers_dir.is_dir():
        candidates.extend(p for p in sorted(sudoers_dir.iterdir()) if p.is_file())
    findings: list[Finding] = []
    for candidate in candidates:
        content = _read_text(candidate)
        if content is None:
            continue
        for line in content.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "NOPASSWD" in stripped:
                findings.append(Finding(
                    check="sudo-nopasswd",
                    title=f"Passwordless sudo rule in {candidate.name}",
                    severity="medium",
                    detail=stripped[:120],
                    recommendation="Require a password for sudo, or scope the rule to a "
                    "single command instead of ALL.",
                ))
    return findings


def _parse_proc_net_tcp(path: Path, protocol: str) -> list[dict]:
    """Parse /proc/net/tcp(6) for LISTEN sockets."""
    content = _read_text(path)
    if content is None:
        return []
    listeners: list[dict] = []
    for line in content.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[3] != "0A":  # 0A == LISTEN
            continue
        local = fields[1]
        _, _, port_hex = local.rpartition(":")
        try:
            port = int(port_hex, 16)
        except ValueError:
            continue
        listeners.append({"protocol": protocol, "port": port})
    return listeners


def collect_listeners() -> list[dict]:
    """Listening TCP sockets, cross-platform."""
    if _is_posix():
        listeners = _parse_proc_net_tcp(Path("/proc/net/tcp"), "tcp4")
        listeners += _parse_proc_net_tcp(Path("/proc/net/tcp6"), "tcp6")
        return listeners
    listeners: list[dict] = []
    try:
        result = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return listeners
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0].upper() == "TCP" and "LISTEN" in parts[3].upper():
            _, _, port_text = parts[1].rpartition(":")
            try:
                listeners.append({"protocol": "tcp", "port": int(port_text)})
            except ValueError:
                continue
    return listeners


def check_listening_ports() -> list[Finding]:
    findings: list[Finding] = []
    listeners = collect_listeners()
    unique_ports = sorted({item["port"] for item in listeners})
    for port in unique_ports:
        if port in RISKY_LISTENER_PORTS:
            findings.append(Finding(
                check="listening-ports",
                title=f"Risky service listening on port {port}",
                severity="medium",
                detail=RISKY_LISTENER_PORTS[port],
                recommendation="Disable the service if unused, or bind it to localhost "
                "and firewall it.",
            ))
    findings.append(Finding(
        check="listening-ports",
        title=f"{len(unique_ports)} TCP port(s) listening",
        severity="info",
        detail=", ".join(str(p) for p in unique_ports) or "none",
        recommendation="Every open port is attack surface — close what you don't use.",
    ))
    return findings


def _startup_entries_posix() -> list[dict]:
    entries: list[dict] = []
    for autostart_dir in (Path.home() / ".config" / "autostart", Path("/etc/xdg/autostart")):
        if not autostart_dir.is_dir():
            continue
        for desktop_file in sorted(autostart_dir.glob("*.desktop")):
            content = _read_text(desktop_file) or ""
            name = desktop_file.stem
            exec_line = ""
            for line in content.splitlines():
                if line.startswith("Name="):
                    name = line.partition("=")[2].strip()
                elif line.startswith("Exec="):
                    exec_line = line.partition("=")[2].strip()
            entries.append({"source": str(autostart_dir), "name": name, "command": exec_line})
    for cron_path in (Path("/etc/crontab"),):
        if cron_path.is_file():
            entries.append({"source": str(cron_path), "name": "system crontab", "command": ""})
    cron_d = Path("/etc/cron.d")
    if cron_d.is_dir():
        for cron_file in sorted(cron_d.iterdir()):
            if cron_file.is_file():
                entries.append({"source": str(cron_d), "name": cron_file.name, "command": ""})
    return entries


def _startup_entries_windows() -> list[dict]:
    entries: list[dict] = []
    try:
        import winreg  # type: ignore
    except ImportError:
        winreg = None
    if winreg is not None:
        for hive, hive_name in (
            (winreg.HKEY_CURRENT_USER, "HKCU"),
            (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
        ):
            for subkey in (r"Software\Microsoft\Windows\CurrentVersion\Run",
                           r"Software\Microsoft\Windows\CurrentVersion\RunOnce"):
                try:
                    with winreg.OpenKey(hive, subkey) as key:
                        index = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, index)
                            except OSError:
                                break
                            entries.append({
                                "source": f"{hive_name}\\{subkey}",
                                "name": name,
                                "command": str(value),
                            })
                            index += 1
                except OSError:
                    continue
    startup_dir = (
        Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows"
        / "Start Menu" / "Programs" / "Startup"
    )
    if startup_dir.is_dir():
        for item in sorted(startup_dir.iterdir()):
            entries.append({"source": str(startup_dir), "name": item.name, "command": str(item)})
    return entries


def check_startup_items() -> list[Finding]:
    """Persistence inventory — everything that launches at boot/login."""
    entries = _startup_entries_posix() if _is_posix() else _startup_entries_windows()
    findings: list[Finding] = []
    temp_markers = ("/tmp", "/var/tmp", "/dev/shm", "\\temp\\", "\\tmp\\")
    for entry in entries:
        command = entry.get("command", "").lower()
        if command and any(marker in command for marker in temp_markers):
            findings.append(Finding(
                check="startup-items",
                title=f"Startup item launches from a temp directory: {entry['name']}",
                severity="high",
                detail=f"{entry['source']}: {entry['command'][:120]}",
                recommendation="Legitimate software does not persist from temp folders. "
                "Remove and rescan for malware.",
            ))
    findings.append(Finding(
        check="startup-items",
        title=f"{len(entries)} startup/persistence entries found",
        severity="info",
        detail=", ".join(entry["name"] for entry in entries[:20])
        + (" ..." if len(entries) > 20 else ""),
        recommendation="Review the list; attackers survive reboots via autostart, cron "
        "and Run keys.",
    ))
    return findings


ALL_CHECKS = {
    "file-permissions": check_sensitive_file_permissions,
    "world-writable": check_world_writable,
    "suid-sgid": check_suid_sgid,
    "accounts": check_accounts,
    "sshd-config": check_sshd_config,
    "sudo-nopasswd": check_sudo_nopasswd,
    "listening-ports": check_listening_ports,
    "startup-items": check_startup_items,
}


def run_audit(only: list[str] | None = None) -> AuditReport:
    report = AuditReport(
        created=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        hostname=socket.gethostname(),
        platform=sys.platform,
    )
    selected = only or list(ALL_CHECKS)
    for name in selected:
        check = ALL_CHECKS.get(name)
        if check is None:
            continue
        try:
            report.findings.extend(check())
        except Exception as exc:  # one broken check must not sink the audit
            report.findings.append(Finding(
                check=name,
                title=f"Check '{name}' failed to run",
                severity="info",
                detail=str(exc),
            ))
    return report


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

_SEVERITY_BADGE = {
    "critical": "[CRIT]",
    "high": "[HIGH]",
    "medium": "[MED ]",
    "low": "[LOW ]",
    "info": "[INFO]",
}


def print_report(report: AuditReport) -> None:
    print(f"\n=== {APP_NAME} security posture audit ===")
    print(f"Host: {report.hostname} | Platform: {report.platform} | {report.created}")
    counts = report.counts()
    print(
        "Findings: "
        + ", ".join(f"{sev}={counts[sev]}" for sev in SEVERITIES if counts[sev])
    )
    print(f"Score: {report.score}/100 (grade {report.grade})\n")

    ordered = sorted(report.findings, key=lambda f: SEVERITIES.index(f.severity))
    for finding in ordered:
        if finding.severity == "info" and finding.title.startswith("0 "):
            continue
        print(f"{_SEVERITY_BADGE[finding.severity]} {finding.title}")
        if finding.detail and finding.severity != "info":
            print(f"       {finding.detail}")
        if finding.recommendation and finding.severity in ("critical", "high", "medium"):
            print(f"       fix: {finding.recommendation}")
    print()


def write_json_report(report: AuditReport, path: Path) -> None:
    payload = {
        "created": report.created,
        "hostname": report.hostname,
        "platform": report.platform,
        "score": report.score,
        "grade": report.grade,
        "counts": report.counts(),
        "findings": [asdict(f) for f in report.findings],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_html_report(report: AuditReport, path: Path) -> None:
    rows = []
    for finding in sorted(report.findings, key=lambda f: SEVERITIES.index(f.severity)):
        rows.append(
            "<tr class='{sev}'><td>{sev}</td><td>{check}</td><td>{title}</td>"
            "<td>{detail}</td><td>{rec}</td></tr>".format(
                sev=html.escape(finding.severity),
                check=html.escape(finding.check),
                title=html.escape(finding.title),
                detail=html.escape(finding.detail),
                rec=html.escape(finding.recommendation),
            )
        )
    document = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{APP_NAME} audit — {html.escape(report.hostname)}</title>
<style>
body {{ background:#0f1410; color:#d9e6d0; font-family:system-ui,sans-serif; margin:2rem; }}
h1 {{ color:#a3e635; }} table {{ border-collapse:collapse; width:100%; }}
td, th {{ border:1px solid #29402a; padding:.5rem .75rem; text-align:left; vertical-align:top; }}
tr.critical td {{ color:#f87171; }} tr.high td {{ color:#fb923c; }}
tr.medium td {{ color:#facc15; }} tr.low td {{ color:#93c5fd; }} tr.info td {{ color:#9ca3af; }}
.grade {{ font-size:3rem; color:#a3e635; }}
</style></head><body>
<h1>{APP_NAME} — security posture audit</h1>
<p>Host: {html.escape(report.hostname)} · Platform: {html.escape(report.platform)} · {html.escape(report.created)}</p>
<p class="grade">Grade {report.grade} ({report.score}/100)</p>
<table><tr><th>Severity</th><th>Check</th><th>Finding</th><th>Detail</th><th>Recommendation</th></tr>
{''.join(rows)}
</table></body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME.lower(),
        description="Read-only local security posture audit. Never modifies the system.",
    )
    parser.add_argument("--list-checks", action="store_true", help="List available checks and exit.")
    parser.add_argument("--only", help="Comma-separated subset of checks to run.")
    parser.add_argument("--json", help="Write a JSON report to this path.")
    parser.add_argument("--html", help="Write an HTML report to this path.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_checks:
        print("Available checks:")
        for name in ALL_CHECKS:
            print(f"  - {name}")
        return 0

    only = None
    if args.only:
        only = [name.strip() for name in args.only.split(",") if name.strip()]
        unknown = [name for name in only if name not in ALL_CHECKS]
        if unknown:
            print(f"Unknown check(s): {', '.join(unknown)}", file=sys.stderr)
            print(f"Run --list-checks to see options.", file=sys.stderr)
            return 2

    report = run_audit(only)
    print_report(report)
    if args.json:
        write_json_report(report, Path(args.json))
        print(f"JSON report written to {args.json}")
    if args.html:
        write_html_report(report, Path(args.html))
        print(f"HTML report written to {args.html}")

    worst = min(report.findings, key=lambda f: SEVERITIES.index(f.severity), default=None)
    if worst and SEVERITIES.index(worst.severity) <= SEVERITIES.index("high"):
        return 1  # script-friendly: 1 == critical/high findings present
    return 0


if __name__ == "__main__":
    sys.exit(main())
