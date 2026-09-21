import os
import stat
import tempfile
import unittest
from pathlib import Path

from cobraaudit import (
    AuditReport,
    Finding,
    check_accounts,
    check_sensitive_file_permissions,
    check_sshd_config,
    run_audit,
)


class GradeTests(unittest.TestCase):
    def _report(self, severities):
        return AuditReport(
            created="",
            hostname="test",
            platform="test",
            findings=[Finding(check="c", title="t", severity=s) for s in severities],
        )

    def test_clean_report_scores_100_grade_a(self) -> None:
        report = self._report([])
        self.assertEqual(report.score, 100)
        self.assertEqual(report.grade, "A")

    def test_weights_deduct_correctly(self) -> None:
        report = self._report(["critical", "medium", "low"])
        self.assertEqual(report.score, 100 - 25 - 8 - 3)

    def test_score_never_negative(self) -> None:
        report = self._report(["critical"] * 10)
        self.assertEqual(report.score, 0)
        self.assertEqual(report.grade, "F")

    def test_counts(self) -> None:
        report = self._report(["high", "high", "info"])
        self.assertEqual(report.counts()["high"], 2)
        self.assertEqual(report.counts()["info"], 1)
        self.assertEqual(report.counts()["critical"], 0)


@unittest.skipUnless(os.name == "posix", "POSIX-only checks")
class AccountCheckTests(unittest.TestCase):
    def test_flags_uid_zero_backdoor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            passwd = Path(tmp) / "passwd"
            passwd.write_text(
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "evil:x:0:0::/home/evil:/bin/bash\n",
                encoding="utf-8",
            )
            findings = check_accounts(passwd)
        critical = [f for f in findings if f.severity == "critical"]
        self.assertEqual(len(critical), 1)
        self.assertIn("evil", critical[0].title)

    def test_flags_empty_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            passwd = Path(tmp) / "passwd"
            passwd.write_text("nopass::1000:1000::/home/nopass:/bin/bash\n", encoding="utf-8")
            findings = check_accounts(passwd)
        self.assertTrue(any(f.severity == "high" for f in findings))

    def test_clean_passwd_produces_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            passwd = Path(tmp) / "passwd"
            passwd.write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")
            self.assertEqual(check_accounts(passwd), [])


@unittest.skipUnless(os.name == "posix", "POSIX-only checks")
class SshdConfigTests(unittest.TestCase):
    def test_flags_root_login_and_empty_passwords(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "sshd_config"
            config.write_text(
                "PermitRootLogin yes\nPermitEmptyPasswords yes\nPasswordAuthentication no\n",
                encoding="utf-8",
            )
            findings = check_sshd_config(config)
        severities = {f.severity for f in findings}
        self.assertIn("critical", severities)
        self.assertFalse(any("password authentication" in f.title.lower() for f in findings))

    def test_comments_and_blank_lines_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "sshd_config"
            config.write_text("#PermitRootLogin yes\n\nPermitRootLogin no\n", encoding="utf-8")
            findings = check_sshd_config(config)
        self.assertFalse(any("root login" in f.title.lower() for f in findings))


@unittest.skipUnless(os.name == "posix", "POSIX-only checks")
class FilePermissionTests(unittest.TestCase):
    def test_flags_readable_private_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            ssh_dir = home / ".ssh"
            ssh_dir.mkdir(mode=0o700)
            key = ssh_dir / "id_ed25519"
            key.write_text("fake-key", encoding="utf-8")
            key.chmod(0o644)
            findings = check_sensitive_file_permissions(home)
        self.assertTrue(any(f.severity == "critical" for f in findings))

    def test_correct_permissions_are_quiet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            ssh_dir = home / ".ssh"
            ssh_dir.mkdir(mode=0o700)
            ssh_dir.chmod(0o700)
            key = ssh_dir / "id_ed25519"
            key.write_text("fake-key", encoding="utf-8")
            key.chmod(0o600)
            findings = check_sensitive_file_permissions(home)
        self.assertFalse(any(f.severity == "critical" for f in findings))


class RunAuditTests(unittest.TestCase):
    def test_run_audit_collects_findings_without_raising(self) -> None:
        report = run_audit()
        self.assertIsInstance(report, AuditReport)
        self.assertIsInstance(report.score, int)

    def test_only_subset(self) -> None:
        report = run_audit(only=["listening-ports"])
        checks = {f.check for f in report.findings}
        self.assertTrue(checks <= {"listening-ports"})


if __name__ == "__main__":
    unittest.main()
