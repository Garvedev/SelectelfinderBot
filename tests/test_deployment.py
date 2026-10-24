"""Exercise the real installer with fake systemctl/Python, without sudo."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")
if os.name == "nt":
    git_bash = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"
    BASH = str(git_bash) if git_bash.exists() else None


def shell_path(path):
    value = str(path.resolve()).replace("\\", "/")
    return f"/{value[0].lower()}{value[2:]}" if os.name == "nt" else value


@unittest.skipUnless(BASH, "Bash is required for installer tests")
class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="selectel-deploy-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.app = self.root / "app"
        self.units = self.root / "units"
        self.bin = self.root / "bin"
        self.calls = self.root / "calls.log"
        for directory in (self.app / "systemd", self.app / ".venv/bin", self.units, self.bin):
            directory.mkdir(parents=True, exist_ok=True)
        for filename in ("deploy.sh", "deploy_swiftshield_watchdog.sh"):
            shutil.copyfile(PROJECT / filename, self.app / filename)
        shutil.copyfile(PROJECT / "systemd/swiftshield-watchdog.service", self.app / "systemd/swiftshield-watchdog.service")
        (self.app / ".venv/bin/activate").write_text('export PATH="$APP_DIR/.venv/bin:$PATH"\n', encoding="utf-8")
        self.write_command(self.app / ".venv/bin/python", """
if [[ "$*" == *--check-config* ]]; then
    echo preflight >> "$COMMAND_LOG"
    exit "${PREFLIGHT_EXIT:-0}"
fi
""")
        self.write_command(self.bin / "python3", "exit 0\n")
        self.write_command(self.bin / "sleep", "exit 0\n")
        self.write_command(self.bin / "systemctl", """
echo "systemctl $*" >> "$COMMAND_LOG"
if [[ "$1" == "is-active" && "${INACTIVE:-0}" == "1" ]]; then exit 1; fi
""")
        self.write_command(self.bin / "journalctl", 'echo "journalctl $*" >> "$COMMAND_LOG"\n')
        self.env = {
            **os.environ, "APP_DIR": shell_path(self.app),
            "SYSTEMD_UNIT_DIR": shell_path(self.units), "SERVICE_USER": "root",
            "SERVICE_GROUP": "root", "SERVICE_NAME": "swiftshield-watchdog",
            "TEST_BIN": shell_path(self.bin), "COMMAND_LOG": shell_path(self.calls),
            "SKIP_GIT_PULL": "true", "PREFLIGHT_EXIT": "0", "INACTIVE": "0",
        }

    @staticmethod
    def write_command(path, body):
        with path.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write("#!/bin/bash\nset -euo pipefail\n" + body)
        path.chmod(0o755)

    def run_installer(self, entrypoint="deploy_swiftshield_watchdog.sh", **overrides):
        return subprocess.run(
            [BASH, "-c", 'export PATH="$TEST_BIN:$PATH"; exec bash "$APP_DIR/$ENTRYPOINT"'],
            env={**self.env, "ENTRYPOINT": entrypoint, **overrides},
            capture_output=True, text=True, timeout=20,
        )

    def test_ci_entrypoint_installs_and_enables_service_and_disables_legacy_units(self):
        (self.units / "swiftshield-watchdog.timer").touch()
        (self.units / "finder.service").touch()
        result = self.run_installer(entrypoint="deploy.sh")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls.read_text().splitlines()
        self.assertEqual(calls, [
            "preflight", "systemctl disable --now finder.service",
            "systemctl disable --now swiftshield-watchdog.timer",
            "systemctl daemon-reload", "systemctl enable swiftshield-watchdog.service",
            "systemctl restart swiftshield-watchdog.service",
            "systemctl is-active --quiet swiftshield-watchdog.service",
            "systemctl is-enabled --quiet swiftshield-watchdog.service",
            "systemctl status swiftshield-watchdog.service --no-pager",
        ])
        unit = (self.units / "swiftshield-watchdog.service").read_text()
        self.assertIn(f"WorkingDirectory={shell_path(self.app)}", unit)
        self.assertIn(f"ExecStart={shell_path(self.app)}/.venv/bin/python {shell_path(self.app)}/swiftshield_watchdog.py --loop", unit)
        self.assertIn("WantedBy=multi-user.target", unit)

    def test_first_install_with_custom_service_name(self):
        result = self.run_installer(SERVICE_NAME="custom-watchdog")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.units / "custom-watchdog.service").is_file())
        calls = self.calls.read_text()
        self.assertIn("systemctl restart custom-watchdog.service", calls)
        self.assertNotIn("disable --now", calls)

    def test_invalid_config_preserves_existing_services(self):
        (self.units / "swiftshield-watchdog.timer").touch()
        (self.units / "finder.service").touch()
        result = self.run_installer(PREFLIGHT_EXIT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls.read_text().splitlines(), ["preflight"])
        self.assertFalse((self.units / "swiftshield-watchdog.service").exists())

    def test_inactive_service_fails_deploy_and_prints_journal(self):
        result = self.run_installer(INACTIVE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("journalctl -u swiftshield-watchdog.service", self.calls.read_text())


if __name__ == "__main__":
    unittest.main()
