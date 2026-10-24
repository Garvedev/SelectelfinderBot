import contextlib
import io
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import yaml

from selectel_cloud import SelectelCloudConfig, make_cloud_init_script
from test_deployment import BASH


PROJECT = Path(__file__).resolve().parents[1]


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.safe_load((PROJECT / ".github/workflows/deploy.yml").read_text(encoding="utf-8"))

    def test_production_credentials_are_scoped_to_steps_and_main_branch(self):
        job = self.workflow["jobs"]["deploy"]
        self.assertEqual(job["if"], "github.ref == 'refs/heads/main'")
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertNotIn("ENV_FILE", job["env"])
        self.assertNotIn("DEPLOY_SSH_KEY", job["env"])
        cleanup = job["steps"][-1]
        self.assertEqual(cleanup["if"], "always()")

    def test_ci_masks_individual_credentials_without_masking_port_numbers(self):
        upload = next(step for step in self.workflow["jobs"]["deploy"]["steps"] if "ENV_FILE" in step.get("env", {}))
        code = upload["run"].split("python3 - <<'PY'\n", 1)[1].split("\nPY", 1)[0]
        fake_password = "audit-test-" + "password"
        fake_env = f'OS_PASSWORD="{fake_password}"\nSWIFTSHIELD_CHECK_INTERVAL_SECONDS=30\nSWIFTSHIELD_ENABLED=true\n'
        with patch.dict(os.environ, {"ENV_FILE": fake_env}), contextlib.redirect_stdout(io.StringIO()) as captured:
            exec(compile(code, "workflow-mask", "exec"), {})
        commands = captured.getvalue().splitlines()
        self.assertIn("::add-mask::" + fake_password, commands)
        self.assertNotIn("::add-mask::30", commands)
        self.assertNotIn("::add-mask::true", commands)

    @unittest.skipUnless(BASH, "Bash is required to check shell escaping")
    def test_cloud_init_origin_is_literal_and_cannot_execute_shell_expansion(self):
        origin = "192.0.2.1$(printf INJECTED)'quoted"
        script = make_cloud_init_script(SelectelCloudConfig(provision_origin_ip=origin))
        export = next(line for line in script.splitlines() if line.startswith("export ORIGIN_IP="))
        result = subprocess.run([BASH, "-c", export + '\nprintf "%s" "$ORIGIN_IP"'], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, origin)


if __name__ == "__main__":
    unittest.main()
