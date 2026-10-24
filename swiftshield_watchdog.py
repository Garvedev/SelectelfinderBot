import argparse
import json
import os
import re
import signal
import sys
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path

import requests
from dotenv import load_dotenv

from selectel_cloud import OpenStackConfig, close_connection, get_connection, tcp_connect_ok


load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_STATE_FILE = BASE_DIR / "swiftshield_watchdog_state.json"


def optional_env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def int_env(name: str, default: int, minimum: int = 0) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < minimum:
        raise RuntimeError(f"{name} must be >= {minimum}")
    return value


def redacted(value: str) -> str:
    text = str(value or "")
    for name in (
        "TELEGRAM_BOT_TOKEN", "OS_PASSWORD",
        "SWIFTSHIELD_OPENSTACK_PROXY", "OPENSTACK_PROXY", "SOCKS5_PROXY",
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
        "http_proxy", "https_proxy", "all_proxy",
    ):
        secret = optional_env(name)
        if secret and len(secret) >= 6:
            text = text.replace(secret, f"[REDACTED:{name}]")
    return text


def redacted_data(value):
    # Redact string values before JSON encoding, including passwords with
    # quotes, backslashes or non-ASCII characters, without breaking JSON.
    if isinstance(value, dict):
        return {key: redacted_data(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redacted_data(item) for item in value]
    return redacted(value) if isinstance(value, str) else value


def openstack_no_proxy_value() -> str:
    values = [item.strip() for item in optional_env("OPENSTACK_NO_PROXY", "127.0.0.1,localhost").split(",") if item.strip()]
    existing = {item.lower() for item in values}
    for required in ("127.0.0.1", "localhost"):
        if required not in existing:
            values.append(required)
    return ",".join(values)


def configure_openstack_proxy() -> None:
    proxy = optional_env("SWIFTSHIELD_OPENSTACK_PROXY") or optional_env("OPENSTACK_PROXY")
    fallback = bool_env("SWIFTSHIELD_OPENSTACK_PROXY_FALLBACK_TO_SOCKS5_PROXY", False)
    if not proxy and fallback:
        proxy = optional_env("SOCKS5_PROXY")

    if not proxy:
        # Recovery must not inherit a proxy hosted on the failed target VM.
        for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
            os.environ.pop(name, None)
        return

    no_proxy = openstack_no_proxy_value()
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
        os.environ[name] = proxy
    os.environ["NO_PROXY"] = no_proxy
    os.environ["no_proxy"] = no_proxy


def openstack_config() -> OpenStackConfig:
    auth_url = optional_env("OS_AUTH_URL")
    username = optional_env("OS_USERNAME")
    password = optional_env("OS_PASSWORD")
    project_id = optional_env("OS_PROJECT_ID")
    project_name = optional_env("OS_PROJECT_NAME")

    missing = []
    if not auth_url:
        missing.append("OS_AUTH_URL")
    if not username:
        missing.append("OS_USERNAME")
    if not password:
        missing.append("OS_PASSWORD")
    if not project_id and not project_name:
        missing.append("OS_PROJECT_ID or OS_PROJECT_NAME")
    if missing:
        raise RuntimeError(f"Missing OpenStack settings: {', '.join(missing)}")

    return OpenStackConfig(
        auth_url=auth_url,
        project_id=project_id,
        project_name=project_name,
        username=username,
        password=password,
        user_domain_name=optional_env("OS_USER_DOMAIN_NAME", "Default"),
        project_domain_name=optional_env("OS_PROJECT_DOMAIN_NAME", "Default"),
        interface=optional_env("OS_INTERFACE", "public"),
        identity_api_version=optional_env("OS_IDENTITY_API_VERSION", "3"),
        compute_api_version=optional_env("OS_COMPUTE_API_VERSION", "2.72"),
        api_timeout=int_env("SWIFTSHIELD_API_TIMEOUT", 10, minimum=1),
        connect_retries=0,
    )


def split_region_and_zone(raw_region: str) -> tuple[str, str]:
    region = raw_region.strip()
    match = re.fullmatch(r"(ru-\d+)[a-z]", region)
    if match:
        return match.group(1), ""
    return region, ""


@dataclass
class WatchdogConfig:
    enabled: bool
    region: str
    availability_zone: str
    server_id: str
    server_name: str
    wait_seconds: int
    dry_run: bool
    notify_telegram: bool
    notify_always: bool
    notify_repeat_seconds: int
    state_file: Path
    interval_seconds: int = 30
    health_host: str = ""
    health_port: int = 443
    health_timeout: int = 3
    operation_timeout_seconds: int = 300


def watchdog_config(dry_run_override: bool = False) -> WatchdogConfig:
    raw_region = optional_env("SWIFTSHIELD_REGION", optional_env("OS_REGION_NAME", ""))
    if not raw_region:
        raise RuntimeError("SWIFTSHIELD_REGION or OS_REGION_NAME must be set")

    region, inferred_zone = split_region_and_zone(raw_region)
    availability_zone = optional_env("SWIFTSHIELD_AVAILABILITY_ZONE", inferred_zone)

    server_id = optional_env("SWIFTSHIELD_SERVER_ID")
    server_name = optional_env("SWIFTSHIELD_SERVER_NAME", "SwiftShield1")
    if not server_id and not server_name:
        raise RuntimeError("SWIFTSHIELD_SERVER_ID or SWIFTSHIELD_SERVER_NAME must be set")

    state_file_raw = optional_env("SWIFTSHIELD_STATE_FILE", str(DEFAULT_STATE_FILE))

    return WatchdogConfig(
        enabled=bool_env("SWIFTSHIELD_ENABLED", False),
        region=region,
        availability_zone=availability_zone,
        server_id=server_id,
        server_name=server_name,
        wait_seconds=int_env("SWIFTSHIELD_WAIT_SECONDS", 0),
        dry_run=dry_run_override or bool_env("SWIFTSHIELD_DRY_RUN", False),
        notify_telegram=bool_env("SWIFTSHIELD_NOTIFY_TELEGRAM", True),
        notify_always=bool_env("SWIFTSHIELD_NOTIFY_ALWAYS", False),
        notify_repeat_seconds=int_env("SWIFTSHIELD_NOTIFY_REPEAT_SECONDS", 3600),
        state_file=Path(state_file_raw),
        interval_seconds=int_env("SWIFTSHIELD_CHECK_INTERVAL_SECONDS", 30, minimum=1),
        health_host=optional_env("SWIFTSHIELD_HEALTH_HOST"),
        health_port=int_env("SWIFTSHIELD_HEALTH_PORT", 443, minimum=1),
        health_timeout=int_env("SWIFTSHIELD_HEALTH_TIMEOUT", 3, minimum=1),
        operation_timeout_seconds=int_env("SWIFTSHIELD_OPERATION_TIMEOUT_SECONDS", 300, minimum=1),
    )


def find_target_server(conn, config: WatchdogConfig):
    errors = []

    if config.server_id:
        # An explicit ID is authoritative. Never operate on a different VM
        # after a transient API failure or after the configured VM is deleted.
        return conn.compute.get_server(config.server_id)

    if config.server_name:
        try:
            server = conn.compute.find_server(config.server_name, ignore_missing=True)
            if server:
                return server
            errors.append(f"name={config.server_name}: not found")
        except Exception as exc:
            errors.append(f"name={config.server_name}: {type(exc).__name__}: {exc}")

    raise RuntimeError(f"Server lookup failed in {config.region}: {'; '.join(errors)}")


def server_status(server) -> str:
    return str(getattr(server, "status", "") or "").upper()


def server_summary(server) -> dict:
    return {
        "id": getattr(server, "id", ""),
        "name": getattr(server, "name", ""),
        "status": server_status(server),
        "vm_state": getattr(server, "vm_state", None),
        "task_state": getattr(server, "task_state", None),
        "power_state": getattr(server, "power_state", None),
        "fault": getattr(server, "fault", None),
    }


def wait_active(conn, server, wait_seconds: int):
    if wait_seconds <= 0:
        return server
    return conn.compute.wait_for_server(
        server,
        status="ACTIVE",
        failures=["ERROR"],
        interval=5,
        wait=wait_seconds,
    )


def ensure_server_running(conn, server, config: WatchdogConfig) -> dict:
    status = server_status(server)
    result = {
        "ok": True,
        "changed": False,
        "action": "noop",
        "message": "",
        "before": server_summary(server),
        "after": None,
    }

    if getattr(server, "task_state", None) and status != "ERROR":
        result["action"] = "wait"
        result["message"] = f"Operation in progress: {server.task_state}"
        return result

    if status == "ACTIVE":
        result["message"] = "Server is already ACTIVE"
        if config.health_host:
            healthy = tcp_connect_ok(config.health_host, config.health_port, config.health_timeout)
            result["health_ok"] = healthy
            if not healthy:
                result["ok"] = False
                result["action"] = "health_check_failed"
                result["message"] = (
                    f"VM is ACTIVE but TCP/{config.health_port} is unreachable; "
                    "check the guest service, firewall and network"
                )
        return result

    actions = {
        "SHUTOFF": ("start", conn.compute.start_server),
        "STOPPED": ("start", conn.compute.start_server),
        "SHELVED": ("unshelve", conn.compute.unshelve_server),
        "SHELVED_OFFLOADED": ("unshelve", conn.compute.unshelve_server),
        "EXPIRED": ("unshelve", conn.compute.unshelve_server),
        "PAUSED": ("unpause", conn.compute.unpause_server),
        "SUSPENDED": ("resume", conn.compute.resume_server),
    }
    if status in actions:
        action, operation = actions[status]
        result["action"] = action
        if config.dry_run:
            result["message"] = f"Dry run: would {action} server"
            return result
        kwargs = {}
        # Nova only allows selecting an AZ for an offloaded server (>=2.77).
        if action == "unshelve" and status in {"SHELVED_OFFLOADED", "EXPIRED"} and config.availability_zone:
            version = optional_env("OS_COMPUTE_API_VERSION", "2.72")
            if version != "latest" and tuple(int(part) for part in version.split(".")) < (2, 77):
                raise RuntimeError("SWIFTSHIELD_AVAILABILITY_ZONE requires OS_COMPUTE_API_VERSION >= 2.77")
            kwargs["availability_zone"] = config.availability_zone
        try:
            operation(server, **kwargs)
            result["changed"] = True
            result["pending"] = True
            result["message"] = f"{action} requested; ACTIVE will be checked on the next cycle"
            if config.wait_seconds > 0:
                fresh = wait_active(conn, server, config.wait_seconds)
                result["after"] = server_summary(fresh)
                result["pending"] = server_status(fresh) != "ACTIVE"
        except Exception as exc:
            result["ok"] = False
            result["message"] = f"{action} failed: {type(exc).__name__}: {exc}"
        return result

    if status == "ERROR":
        result["ok"] = False
        result["action"] = "manual_check"
        result["message"] = "Server is in ERROR; manual rebuild/recreate may be required"
        return result

    transitional = {"BUILD", "REBOOT", "HARD_REBOOT", "REBUILD", "MIGRATING", "RESIZE", "REVERT_RESIZE", "PASSWORD"}
    result["ok"] = status in transitional
    result["action"] = "wait" if result["ok"] else "manual_check"
    result["message"] = f"Server status is {status or 'UNKNOWN'}; no automatic recovery action"
    return result


def load_state(path: Path) -> dict:
    try:
        if path.exists():
            state = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(state, dict):
                return {}
            for key in ("last_observation", "pending_launch", "last_result"):
                if key in state and not isinstance(state[key], dict):
                    return {}
            for key in ("last_run_at", "last_notification_at", "last_launch_at", "last_transition_at", "last_request_at", "operation_started_at"):
                if key in state:
                    # A syntactically valid but damaged timestamp must not
                    # terminate the recovery loop during int conversion.
                    if state[key] is not None and not isinstance(state[key], (int, float, str)):
                        return {}
                    timestamp = int(state[key] or 0)
                    if timestamp < 0:
                        return {}
                    state[key] = timestamp
            return state
    except Exception:
        return {}
    return {}


def save_state(path: Path, state: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(redacted_data(state), ensure_ascii=True, indent=2), encoding="utf-8")
        tmp.replace(path)
    except Exception as exc:
        print(redacted(f"Failed to save state {path}: {exc}"), file=sys.stderr, flush=True)


def notification_text(result: dict, config: WatchdogConfig) -> str:
    before = result.get("before") or {}
    after = result.get("after") or {}
    lines = [
        "SwiftShield watchdog",
        f"server: {before.get('name') or config.server_name}",
        f"id: {before.get('id') or config.server_id}",
        f"region: {config.region}",
        f"status: {before.get('status') or '-'}",
        f"action: {result.get('action')}",
        f"result: {'ok' if result.get('ok') else 'needs attention'}",
        f"message: {result.get('message') or '-'}",
    ]
    if after:
        lines.append(f"after: {after.get('status') or '-'}")
    return "\n".join(lines)


def send_telegram(text: str) -> None:
    token = optional_env("TELEGRAM_BOT_TOKEN")
    chat_id = optional_env("TELEGRAM_ALLOWED_CHAT_ID")
    if not token or not chat_id:
        raise RuntimeError("TELEGRAM_BOT_TOKEN and TELEGRAM_ALLOWED_CHAT_ID are required for notifications")

    response = requests.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data={"chat_id": chat_id, "text": redacted(text)},
        timeout=15,
    )
    response.raise_for_status()


def notification_key(result: dict) -> str:
    before = result.get("before") or {}
    after = result.get("after") or {}
    parts = [
        str(result.get("ok")),
        str(result.get("action")),
        str(before.get("status")),
        str(after.get("status")),
        str(result.get("message")),
    ]
    return redacted("|".join(parts))


def maybe_notify(result: dict, config: WatchdogConfig) -> None:
    if not config.notify_telegram:
        return

    should_notify = config.notify_always or result.get("changed") or result.get("recovered") or not result.get("ok")
    if not should_notify:
        return

    now = int(time.time())
    key = notification_key(result)
    state = load_state(config.state_file)
    last_key = state.get("last_notification_key")
    last_at = int(state.get("last_notification_at") or 0)
    if last_key == key and now - last_at < config.notify_repeat_seconds:
        return

    send_telegram(notification_text(result, config))
    state["last_notification_key"] = key
    state["last_notification_at"] = now
    save_state(config.state_file, state)


def save_last_run(result: dict, config: WatchdogConfig) -> None:
    now = int(time.time())
    state = load_state(config.state_file)
    state["last_run_at"] = now
    before = result.get("before") or {}
    current = result.get("after") or before
    previous = state.get("last_observation") or {}
    observation = {"id": current.get("id"), "status": current.get("status"), "task_state": current.get("task_state")}
    if current:
        if observation != previous:
            state["last_transition_at"] = now
            print(json.dumps(redacted_data({"event": "server_state_changed", "at": now, "before": previous, "after": observation})), flush=True)
        state["last_observation"] = observation
    if config.dry_run:
        # A diagnostic run must not overwrite live recovery/notification state.
        return
    if result.get("action") == "wait":
        if observation != previous or not state.get("operation_started_at"):
            state["operation_started_at"] = now
        busy_seconds = now - int(state["operation_started_at"])
        if busy_seconds >= config.operation_timeout_seconds:
            result["ok"] = False
            result["message"] = f"Operation has not completed within {config.operation_timeout_seconds}s; check provider task state"
    elif current:
        state.pop("operation_started_at", None)
    if result.get("changed"):
        state["last_request_at"] = now
        state["pending_launch"] = {"id": before.get("id"), "action": result.get("action")}
    pending = state.get("pending_launch") or {}
    if current.get("status") == "ACTIVE" and not current.get("task_state") and pending.get("id") == current.get("id") and pending:
        state["last_launch_at"] = now
        state["last_launch_action"] = pending.get("action")
        state["last_launch_status"] = "ACTIVE"
        state.pop("pending_launch", None)
        result["recovered"] = True
    if result.get("ok") and current.get("status") == "ACTIVE":
        # A new outage after recovery must alert even within the repeat window.
        state.pop("last_notification_key", None)
        state.pop("last_notification_at", None)
    state["last_result"] = result
    save_state(config.state_file, state)


def run_once(config: WatchdogConfig) -> dict:
    if not config.enabled:
        return {
            "ok": True,
            "changed": False,
            "action": "disabled",
            "message": "SWIFTSHIELD_ENABLED is false",
        }

    configure_openstack_proxy()
    conn = get_connection(openstack_config(), config.region)
    try:
        server = find_target_server(conn, config)
        return ensure_server_running(conn, server, config)
    finally:
        close_connection(conn)


def execute_check(config: WatchdogConfig) -> int:
    started = time.monotonic()
    try:
        result = run_once(config)
        exit_code = 0 if result.get("ok") else 2
    except Exception as exc:
        result = {
            "ok": False,
            "changed": False,
            "action": "error",
            "message": f"{type(exc).__name__}: {exc}",
        }
        exit_code = 1
    result["checked_at"] = int(time.time())
    result["duration_seconds"] = round(time.monotonic() - started, 3)
    save_last_run(result, config)
    if not config.dry_run:
        try:
            maybe_notify(result, config)
        except Exception as notify_exc:
            print(redacted(f"Telegram notify failed: {notify_exc}"), file=sys.stderr, flush=True)
    print(json.dumps(redacted_data(result), ensure_ascii=False), flush=True)
    return exit_code if result.get("ok") else (exit_code or 2)


def run_loop(config: WatchdogConfig, stop: threading.Event) -> None:
    # Old .env files may still set WAIT_SECONDS=300. In continuous mode no
    # launch wait is allowed to block the next state check.
    config = replace(config, wait_seconds=0)
    while not stop.is_set():
        started = time.monotonic()
        execute_check(config)
        elapsed = time.monotonic() - started
        # Keep start-to-start cadence; on slow APIs skip missed slots instead
        # of overlapping operations or issuing a burst of catch-up requests.
        slots = int(elapsed // config.interval_seconds) + 1
        stop.wait(max(0, slots * config.interval_seconds - elapsed))


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch and restore the Selectel SwiftShield preemptible server.")
    parser.add_argument("--dry-run", action="store_true", help="Print the planned action without changing the server or saved state.")
    parser.add_argument("--loop", action="store_true", help="Check continuously (every 30 seconds by default).")
    parser.add_argument("--check-config", action="store_true", help="Validate production service configuration without cloud requests.")
    args = parser.parse_args()
    try:
        config = watchdog_config(dry_run_override=args.dry_run)
        if not args.loop and not args.check_config:
            return execute_check(config)
        if not config.enabled:
            raise RuntimeError("Set SWIFTSHIELD_ENABLED=true before starting continuous recovery")
        openstack_config()  # Fail early on incomplete credentials.
        if args.check_config:
            if config.dry_run:
                raise RuntimeError("Set SWIFTSHIELD_DRY_RUN=false before deploying the recovery service")
            print(json.dumps({"event": "configuration_valid", "interval_seconds": config.interval_seconds, "region": config.region}), flush=True)
            return 0
        stop = threading.Event()
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, lambda *_: stop.set())
        print(json.dumps({"event": "watchdog_started", "interval_seconds": config.interval_seconds, "region": config.region}), flush=True)
        run_loop(config, stop)
        return 0
    except Exception as exc:
        print(redacted(f"Watchdog failed: {type(exc).__name__}: {exc}"), file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
