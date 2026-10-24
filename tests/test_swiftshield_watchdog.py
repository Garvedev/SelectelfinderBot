import contextlib
import io
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import swiftshield_watchdog as watchdog


def server(status, task_state=None):
    return SimpleNamespace(
        id="target-id", name="SwiftShield1", status=status,
        task_state=task_state, vm_state=None, power_state=None, fault=None,
    )


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = watchdog.WatchdogConfig(
            enabled=True, region="ru-3", availability_zone="",
            server_id="target-id", server_name="SwiftShield1",
            wait_seconds=0, dry_run=False, notify_telegram=False,
            notify_always=False, notify_repeat_seconds=3600,
            state_file=Path(self.tmp.name) / "state.json",
        )
        self.conn = Mock()
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_active_server_is_never_restarted(self):
        result = watchdog.ensure_server_running(self.conn, server("ACTIVE"), self.config)
        self.assertTrue(result["ok"])
        self.assertFalse(result["changed"])
        self.assertEqual(self.conn.mock_calls, [])

    def test_recovery_actions_do_not_wait_for_boot(self):
        for status, method in (
            ("SHUTOFF", "start_server"), ("STOPPED", "start_server"),
            ("SHELVED", "unshelve_server"), ("SHELVED_OFFLOADED", "unshelve_server"),
            ("EXPIRED", "unshelve_server"), ("PAUSED", "unpause_server"),
            ("SUSPENDED", "resume_server"),
        ):
            with self.subTest(status=status):
                conn = Mock()
                vm = server(status)
                result = watchdog.ensure_server_running(conn, vm, self.config)
                getattr(conn.compute, method).assert_called_once_with(vm)
                conn.compute.wait_for_server.assert_not_called()
                self.assertTrue(result["changed"])
                self.assertTrue(result["pending"])
                self.assertIsNone(result["after"])

    def test_no_duplicate_action_while_task_is_running(self):
        for status in ("ACTIVE", "SHUTOFF", "SHELVED_OFFLOADED", "EXPIRED"):
            result = watchdog.ensure_server_running(self.conn, server(status, "powering-on"), self.config)
            self.assertEqual(result["action"], "wait")
        self.assertEqual(self.conn.mock_calls, [])

    def test_dry_run_has_no_mutation_or_false_change(self):
        config = replace(self.config, dry_run=True)
        result = watchdog.ensure_server_running(self.conn, server("SHUTOFF"), config)
        watchdog.save_last_run(result, config)
        self.assertFalse(result["changed"])
        self.assertEqual(self.conn.mock_calls, [])
        self.assertFalse(config.state_file.exists())

    def test_error_unknown_and_deleted_states_need_attention(self):
        for status in ("ERROR", "DELETED", "VERIFY_RESIZE", "", "new-provider-state"):
            with self.subTest(status=status):
                result = watchdog.ensure_server_running(self.conn, server(status), self.config)
                self.assertFalse(result["ok"])
                self.assertEqual(result["action"], "manual_check")
        self.assertEqual(self.conn.mock_calls, [])

    def test_build_is_observed_without_new_actions(self):
        result = watchdog.ensure_server_running(self.conn, server("BUILD"), self.config)
        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], "wait")
        self.assertEqual(self.conn.mock_calls, [])

    def test_explicit_id_never_falls_back_to_name(self):
        self.conn.compute.get_server.side_effect = RuntimeError("API unavailable")
        with self.assertRaisesRegex(RuntimeError, "API unavailable"):
            watchdog.find_target_server(self.conn, self.config)
        self.conn.compute.find_server.assert_not_called()

    def test_lookup_by_name_when_id_is_not_configured(self):
        target = server("SHUTOFF")
        self.conn.compute.find_server.return_value = target
        self.assertIs(watchdog.find_target_server(self.conn, replace(self.config, server_id="")), target)
        self.conn.compute.get_server.assert_not_called()

    def test_capacity_error_preserves_target_state_and_retries(self):
        self.conn.compute.unshelve_server.side_effect = [RuntimeError("No valid host"), None]
        first = watchdog.ensure_server_running(self.conn, server("EXPIRED"), self.config)
        self.assertFalse(first["ok"])
        self.assertFalse(first["changed"])
        self.assertEqual(first["before"]["status"], "EXPIRED")
        second = watchdog.ensure_server_running(self.conn, server("EXPIRED"), self.config)
        self.assertTrue(second["ok"])
        self.assertTrue(second["changed"])
        self.assertEqual(self.conn.compute.unshelve_server.call_count, 2)

    def test_launch_is_confirmed_only_after_active_observation(self):
        requested = watchdog.ensure_server_running(self.conn, server("SHUTOFF"), self.config)
        watchdog.save_last_run(requested, self.config)
        state = watchdog.load_state(self.config.state_file)
        self.assertIn("pending_launch", state)
        self.assertNotIn("last_launch_at", state)
        active = watchdog.ensure_server_running(self.conn, server("ACTIVE"), self.config)
        watchdog.save_last_run(active, self.config)
        state = watchdog.load_state(self.config.state_file)
        self.assertEqual(state["last_launch_status"], "ACTIVE")
        self.assertEqual(state["last_launch_action"], "start")
        self.assertTrue(active["recovered"])
        self.assertNotIn("pending_launch", state)

    def test_notification_of_new_outage_is_not_suppressed(self):
        config = replace(self.config, notify_telegram=True)
        with patch.object(watchdog, "send_telegram") as send:
            for status in ("SHUTOFF", "SHUTOFF", "ACTIVE", "SHUTOFF"):
                result = watchdog.ensure_server_running(self.conn, server(status), config)
                watchdog.save_last_run(result, config)
                watchdog.maybe_notify(result, config)
            # First request, confirmed recovery, second outage. The duplicate
            # SHUTOFF request inside the same incident is suppressed.
            self.assertEqual(send.call_count, 3)

    def test_tcp_failure_alerts_without_restarting_active_vm(self):
        config = replace(self.config, health_host="192.0.2.1")
        with patch.object(watchdog, "tcp_connect_ok", return_value=False) as probe:
            result = watchdog.ensure_server_running(self.conn, server("ACTIVE"), config)
        probe.assert_called_once_with("192.0.2.1", 443, 3)
        self.assertFalse(result["ok"])
        self.assertEqual(result["action"], "health_check_failed")
        self.assertEqual(self.conn.mock_calls, [])

    def test_api_error_does_not_end_next_check(self):
        with patch.object(watchdog, "run_once", side_effect=[RuntimeError("timeout"), {"ok": True, "action": "noop"}]):
            self.assertEqual(watchdog.execute_check(self.config), 1)
            self.assertEqual(watchdog.execute_check(self.config), 0)
        self.assertTrue(watchdog.load_state(self.config.state_file)["last_result"]["ok"])

    def test_notification_failure_does_not_change_recovery_result(self):
        config = replace(self.config, notify_telegram=True)
        result = {"ok": True, "changed": True, "action": "start", "before": {"id": "target-id", "status": "SHUTOFF"}}
        with patch.object(watchdog, "run_once", return_value=result), patch.object(watchdog, "send_telegram", side_effect=RuntimeError("Telegram down")), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(watchdog.execute_check(config), 0)
        self.assertTrue(watchdog.load_state(config.state_file)["last_result"]["changed"])

    def test_loop_uses_start_to_start_cadence_and_ignores_legacy_wait(self):
        stop = Mock()
        stop.is_set.side_effect = [False, False, True]
        with patch.object(watchdog.time, "monotonic", side_effect=[0, 4, 30, 33]), patch.object(watchdog, "execute_check", return_value=1) as check:
            watchdog.run_loop(replace(self.config, wait_seconds=300), stop)
        self.assertEqual(check.call_count, 2)
        self.assertEqual(check.call_args.args[0].wait_seconds, 0)
        self.assertEqual([call.args[0] for call in stop.wait.call_args_list], [26, 27])

    def test_slow_api_skips_missed_slots(self):
        stop = Mock()
        stop.is_set.side_effect = [False, True]
        with patch.object(watchdog.time, "monotonic", side_effect=[0, 65]), patch.object(watchdog, "execute_check"):
            watchdog.run_loop(self.config, stop)
        stop.wait.assert_called_once_with(25)

    def test_shutdown_before_first_check(self):
        stop = Mock()
        stop.is_set.return_value = True
        with patch.object(watchdog, "execute_check") as check:
            watchdog.run_loop(self.config, stop)
        check.assert_not_called()

    def test_connection_closes_even_when_api_lookup_fails(self):
        with patch.object(watchdog, "openstack_config"), patch.object(watchdog, "get_connection", return_value=self.conn), patch.object(watchdog, "find_target_server", side_effect=RuntimeError("timeout")):
            with self.assertRaises(RuntimeError):
                watchdog.run_once(self.config)
        self.conn.close.assert_called_once()

    def test_disabled_mode_makes_no_cloud_calls(self):
        with patch.object(watchdog, "get_connection") as connection:
            result = watchdog.run_once(replace(self.config, enabled=False))
        self.assertEqual(result["action"], "disabled")
        connection.assert_not_called()

    def test_inherited_proxy_is_removed_for_direct_recovery(self):
        with patch.dict(os.environ, {"HTTPS_PROXY": "socks5://failed-vm:1080", "http_proxy": "http://failed-vm:8888"}):
            watchdog.configure_openstack_proxy()
            self.assertNotIn("HTTPS_PROXY", os.environ)
            self.assertNotIn("http_proxy", os.environ)

    def test_explicit_independent_proxy_is_used(self):
        with patch.dict(os.environ, {"SWIFTSHIELD_OPENSTACK_PROXY": "socks5h://independent-host:1080"}):
            watchdog.configure_openstack_proxy()
            self.assertEqual(os.environ["HTTPS_PROXY"], "socks5h://independent-host:1080")

    def test_corrupt_state_file_does_not_block_checks(self):
        for content in ("{broken", "[]", "null", '"text"', '{"pending_launch": "bad"}', '{"last_observation": []}'):
            self.config.state_file.write_text(content, encoding="utf-8")
            self.assertEqual(watchdog.load_state(self.config.state_file), {})
            with patch.object(watchdog, "run_once", return_value={"ok": True}):
                self.assertEqual(watchdog.execute_check(self.config), 0)

    def test_invalid_timestamps_do_not_end_checks(self):
        for field, value in (("operation_started_at", "bad"), ("last_notification_at", {}), ("last_launch_at", -1)):
            self.config.state_file.write_text(json.dumps({field: value}), encoding="utf-8")
            self.assertEqual(watchdog.load_state(self.config.state_file), {})
            with patch.object(watchdog, "run_once", return_value={"ok": True}):
                self.assertEqual(watchdog.execute_check(self.config), 0)

    def test_saved_numeric_timestamp_strings_are_normalized(self):
        self.config.state_file.write_text('{"operation_started_at":"123"}', encoding="utf-8")
        self.assertEqual(watchdog.load_state(self.config.state_file)["operation_started_at"], 123)

    def test_redacted_error_notification_is_deduplicated(self):
        config = replace(self.config, notify_telegram=True)
        result = {"ok": False, "action": "error", "message": "failed secret-password"}
        with patch.dict(os.environ, {"OS_PASSWORD": "secret-password"}), patch.object(watchdog, "send_telegram") as send:
            watchdog.maybe_notify(result, config)
            watchdog.maybe_notify(result, config)
        self.assertEqual(send.call_count, 1)

    def test_secrets_are_redacted_in_logs_and_saved_errors(self):
        password = 'secret-"пароль\\with-quotes'
        with patch.dict(os.environ, {"OS_PASSWORD": password, "TELEGRAM_BOT_TOKEN": "secret-token"}), patch.object(watchdog, "run_once", side_effect=RuntimeError(f"{password} secret-token")):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                watchdog.execute_check(self.config)
            self.assertNotIn("secret-", out.getvalue())
            self.assertNotIn("secret-token", self.config.state_file.read_text())
            message = json.loads(self.config.state_file.read_text())["last_result"]["message"]
            self.assertIn("[REDACTED:OS_PASSWORD]", message)

    def test_stuck_operation_alerts_without_forcing_vm_state(self):
        result = watchdog.ensure_server_running(self.conn, server("SHUTOFF", "powering-on"), self.config)
        with patch.object(watchdog.time, "time", return_value=1000):
            watchdog.save_last_run(result, self.config)
        self.assertTrue(result["ok"])
        result = watchdog.ensure_server_running(self.conn, server("SHUTOFF", "powering-on"), self.config)
        with patch.object(watchdog.time, "time", return_value=1301):
            watchdog.save_last_run(result, self.config)
        self.assertFalse(result["ok"])
        self.assertIn("not completed", result["message"])
        self.assertEqual(self.conn.mock_calls, [])

    def test_error_with_stale_task_state_still_needs_attention(self):
        result = watchdog.ensure_server_running(self.conn, server("ERROR", "powering-on"), self.config)
        self.assertFalse(result["ok"])
        self.assertEqual(result["action"], "manual_check")

    def test_availability_zone_requires_supported_microversion(self):
        config = replace(self.config, availability_zone="ru-3a")
        with self.assertRaisesRegex(RuntimeError, "2.77"):
            watchdog.ensure_server_running(self.conn, server("SHELVED_OFFLOADED"), config)
        self.conn.compute.unshelve_server.assert_not_called()
        with patch.dict(os.environ, {"OS_COMPUTE_API_VERSION": "2.77"}):
            vm = server("SHELVED_OFFLOADED")
            watchdog.ensure_server_running(self.conn, vm, config)
        self.conn.compute.unshelve_server.assert_called_once_with(vm, availability_zone="ru-3a")

    def test_non_offloaded_shelved_does_not_send_zone(self):
        vm = server("SHELVED")
        watchdog.ensure_server_running(self.conn, vm, replace(self.config, availability_zone="ru-3a"))
        self.conn.compute.unshelve_server.assert_called_once_with(vm)

    def test_interval_must_be_positive(self):
        with patch.dict(os.environ, {"SWIFTSHIELD_REGION": "ru-3", "SWIFTSHIELD_CHECK_INTERVAL_SECONDS": "0"}):
            with self.assertRaisesRegex(RuntimeError, "SWIFTSHIELD_CHECK_INTERVAL_SECONDS"):
                watchdog.watchdog_config()

    def test_deploy_preflight_does_not_call_cloud_or_write_state(self):
        with patch("sys.argv", ["watchdog", "--check-config"]), patch.object(watchdog, "watchdog_config", return_value=self.config), patch.object(watchdog, "openstack_config") as auth, patch.object(watchdog, "run_once") as check:
            self.assertEqual(watchdog.main(), 0)
        auth.assert_called_once()
        check.assert_not_called()
        self.assertFalse(self.config.state_file.exists())

    def test_deploy_preflight_rejects_disabled_or_dry_run_mode(self):
        for config in (replace(self.config, enabled=False), replace(self.config, dry_run=True)):
            with patch("sys.argv", ["watchdog", "--check-config"]), patch.object(watchdog, "watchdog_config", return_value=config), patch.object(watchdog, "openstack_config"), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(watchdog.main(), 1)

    def test_deploy_preflight_rejects_missing_credentials(self):
        with patch("sys.argv", ["watchdog", "--check-config"]), patch.object(watchdog, "watchdog_config", return_value=self.config), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(watchdog.main(), 1)


if __name__ == "__main__":
    unittest.main()
