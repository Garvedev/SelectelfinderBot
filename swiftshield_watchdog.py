import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import requests
from dotenv import load_dotenv

from selectel_cloud import OpenStackConfig, close_connection, get_connection


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
    for name in ("TELEGRAM_BOT_TOKEN", "OS_PASSWORD", "SWIFTSHIELD_SERVER_ID"):
        secret = optional_env(name)
        if secret and len(secret) >= 6:
            text = text.replace(secret, f"[REDACTED:{name}]")
    return text


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
        wait_seconds=int_env("SWIFTSHIELD_WAIT_SECONDS", 300),
        dry_run=dry_run_override or bool_env("SWIFTSHIELD_DRY_RUN", False),
        notify_telegram=bool_env("SWIFTSHIELD_NOTIFY_TELEGRAM", True),
        notify_always=bool_env("SWIFTSHIELD_NOTIFY_ALWAYS", False),
        notify_repeat_seconds=int_env("SWIFTSHIELD_NOTIFY_REPEAT_SECONDS", 3600),
        state_file=Path(state_file_raw),
    )


def find_target_server(conn, config: WatchdogConfig):
    errors = []

    if config.server_id:
        try:
            return conn.compute.get_server(config.server_id)
        except Exception as exc:
            errors.append(f"id={config.server_id}: {type(exc).__name__}: {exc}")

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

    if status == "ACTIVE":
        result["message"] = "Server is already ACTIVE"
        return result

    if status in {"SHUTOFF", "STOPPED"}:
        result["action"] = "start"
        result["changed"] = True
        if config.dry_run:
            result["message"] = "Dry run: would start server"
            return result
        conn.compute.start_server(server)
        fresh = wait_active(conn, server, config.wait_seconds)
        result["after"] = server_summary(fresh)
        result["message"] = "Start requested"
        return result

    if status in {"SHELVED", "SHELVED_OFFLOADED"}:
        result["action"] = "unshelve"
        result["changed"] = True
        if config.dry_run:
            result["message"] = "Dry run: would unshelve server"
            return result
        kwargs = {}
        if config.availability_zone:
            kwargs["availability_zone"] = config.availability_zone
        conn.compute.unshelve_server(server, **kwargs)
        fresh = wait_active(conn, server, config.wait_seconds)
        result["after"] = server_summary(fresh)
        result["message"] = "Unshelve requested"
        return result

    if status == "PAUSED":
        result["ok"] = False
        result["action"] = "manual_check"
        result["message"] = "Server is PAUSED; not unpausing automatically"
        return result

    if status == "ERROR":
        result["ok"] = False
        result["action"] = "manual_check"
        result["message"] = "Server is in ERROR; manual rebuild/recreate may be required"
        return result

    result["action"] = "wait"
    result["message"] = f"Server status is {status}; no action"
    return result


def load_state(path: Path) -> dict:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return {}


def save_state(path: Path, state: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=True, indent=2), encoding="utf-8")
        tmp.replace(path)
    except Exception as exc:
        print(f"Failed to save state {path}: {exc}", file=sys.stderr, flush=True)


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
    return "|".join(parts)


def maybe_notify(result: dict, config: WatchdogConfig) -> None:
    if not config.notify_telegram:
        return

    should_notify = config.notify_always or result.get("changed") or not result.get("ok")
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
    state["last_result"] = result
    if (
        result.get("ok")
        and result.get("changed")
        and result.get("action") in {"start", "unshelve"}
        and not config.dry_run
    ):
        after = result.get("after") or {}
        state["last_launch_at"] = now
        state["last_launch_action"] = result.get("action")
        state["last_launch_status"] = after.get("status") or ""
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch and restore the Selectel SwiftShield preemptible server.")
    parser.add_argument("--dry-run", action="store_true", help="Print the planned action without changing the server.")
    args = parser.parse_args()

    config = None

    try:
        config = watchdog_config(dry_run_override=args.dry_run)
        result = run_once(config)
        save_last_run(result, config)
        try:
            maybe_notify(result, config)
        except Exception as notify_exc:
            print(f"Telegram notify failed: {notify_exc}", file=sys.stderr, flush=True)
        print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
        return 0 if result.get("ok") else 2
    except Exception as exc:
        result = {
            "ok": False,
            "changed": False,
            "action": "error",
            "message": str(exc),
        }
        if config is not None:
            save_last_run(result, config)
            try:
                maybe_notify(result, config)
            except Exception as notify_exc:
                print(f"Telegram notify failed: {notify_exc}", file=sys.stderr, flush=True)
        print(json.dumps(result, ensure_ascii=False, indent=2), file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
