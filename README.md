# CobraAudit

Local security posture audit utilities for PCs. A read-only health check that walks your system, ranks findings by severity, and grades the machine A–F. It never modifies anything.

## Features

- **Sensitive file permissions**: flags `~/.ssh` directories and private keys, `~/.netrc`, `~/.pgpass`, AWS credentials, and `/etc/shadow` readable by other users.
- **World-writable sweep**: finds files and folders under your home directory that any local user can tamper with.
- **SUID/SGID inventory**: lists privilege-escalation-capable binaries, with a GTFOBins pointer for triage.
- **Account audit**: detects non-root UID 0 accounts and passwordless accounts in `/etc/passwd` — classic backdoor markers.
- **SSH hardening**: reviews `sshd_config` for root login, password auth, empty passwords and X11 forwarding.
- **Sudo audit**: surfaces `NOPASSWD` rules in `/etc/sudoers` and `/etc/sudoers.d/`.
- **Listening ports**: inventories open TCP listeners and flags risky services (Telnet, FTP, SMB, RDP, VNC, Redis, MongoDB).
- **Startup/persistence audit**: inventories XDG autostart, cron, Windows Run keys and the Startup folder — and flags anything launching from a temp directory.
- **Scored report**: weighted severity scoring → 0–100 score and A–F letter grade, in the terminal, as JSON, or as a dark-themed HTML report.
- **Script-friendly exit codes**: `0` = no critical/high findings, `1` = critical/high findings present, `2` = bad arguments.
- **Read-only & stdlib-only**: Python 3.10+, zero dependencies. Linux/ChromeOS and Windows aware (checks self-skip on platforms they don't apply to).

## Requirements

- Python 3.10+
- Run with `sudo` for full coverage (e.g. `/etc/shadow`, some cron files); without it, checks degrade gracefully.

## Run

Full audit:

```bash
python3 cobraaudit.py
```

List and run a subset of checks:

```bash
python3 cobraaudit.py --list-checks
python3 cobraaudit.py --only sshd-config,accounts,sudo-nopasswd
```

Export reports:

```bash
python3 cobraaudit.py --json audit.json --html audit.html
```

## Scoring

Each finding deducts from 100 by severity: critical −25, high −15, medium −8, low −3, info −0.

| Grade | Score |
| ----- | ----- |
| A | 90+ |
| B | 75–89 |
| C | 60–74 |
| D | 40–59 |
| F | <40 |

## Tests

```bash
python3 -m unittest discover -s tests
```

Tests use synthetic fixture files — no root access or live system state needed.
