import os
import sys
import time
import random
import ipaddress
import re
import threading
import gc
import json
import html
from urllib.parse import unquote
from dataclasses import dataclass, field
from pathlib import Path

import telebot
from telebot import types
from dotenv import load_dotenv

from lists_store import (
    GoodIpRecord,
    ban_ip,
    ip_in_banned_networks,
    is_banned_ip,
    load_approved_region_counts,
    load_approved_ips,
    load_banned_ips,
    load_good_ips,
    managed_lists_snapshot,
    normalize_managed_list_name,
    read_managed_list,
    remove_banned_good_ips,
    remove_good_ip,
    save_approved_key,
    save_good_ip,
    save_managed_list as save_managed_list_file,
    write_good_ips,
)
from selectel_cloud import (
    OpenStackConfig,
    SelectelCloudConfig,
    cleanup_test_server as cloud_cleanup_test_server,
    close_connection as cloud_close_connection,
    create_floating_ip as cloud_create_floating_ip,
    create_test_server as cloud_create_test_server,
    delete_floating_ip as cloud_delete_floating_ip,
    delete_floating_ip_address as cloud_delete_floating_ip_address,
    get_connection as cloud_get_connection,
    get_floating_network as cloud_get_floating_network,
    make_vless_key as cloud_make_vless_key,
    saved_ip_active as cloud_saved_ip_active,
    validate_provision_config as cloud_validate_provision_config,
    wait_for_tcp_port as cloud_wait_for_tcp_port,
)
from dashboard_server import start_tester_api_if_enabled
from telegram_handlers import register_telegram_handlers
from vless_queue import (
    ACTIVE_VLESS_STATUSES,
    IP_NOT_SUITABLE_STATUSES,
    PHONE_FAILURE_STATUSES,
    REVIEW_VLESS_STATUSES,
    active_server_ids,
    audit_log,
    configure_vless_queue,
    dashboard_metrics,
    delete_tester_control_value,
    enqueue_vless_test,
    format_vless_queue_stats,
    get_active_vless_tests,
    get_audit_events,
    get_recent_vless_results,
    get_tester_control_raw,
    get_tester_control_state,
    get_vless_queue_stats,
    get_vless_status_for_ip,
    get_vless_test_by_id,
    get_worker_statuses,
    init_vless_queue,
    is_full_auto_mode_enabled,
    is_provisioning_paused,
    is_testing_paused,
    load_blocking_vless_ips,
    mark_provision_failed as queue_mark_provision_failed,
    mark_region_tests_provision_failed as queue_mark_region_tests_provision_failed,
    mark_test_manual_banned,
    mark_test_provisioning,
    now_ts,
    region_status_rows,
    reserve_vless_tests as queue_reserve_vless_tests,
    reset_vless_test_to_queued,
    save_vless_test_result,
    save_worker_heartbeat,
    select_test_ids,
    set_full_auto_mode,
    set_provisioning_paused,
    set_tester_control_value,
    set_testing_paused,
)

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass


class TeeStream:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for stream in self.streams:
            try:
                stream.write(data)
                stream.flush()
            except Exception:
                pass

    def flush(self):
        for stream in self.streams:
            try:
                stream.flush()
            except Exception:
                pass


def setup_file_logging():
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        log_stream = open(LOG_FILE, "a", encoding="utf-8", buffering=1)
        sys.stdout = TeeStream(sys.__stdout__, log_stream)
        sys.stderr = TeeStream(sys.__stderr__, log_stream)
    except Exception as e:
        print(f"⚠️ Не удалось включить файл логов {LOG_FILE}: {e}", flush=True)


# =========================
# ENV
# =========================

load_dotenv()

DEFAULT_REGIONS = ["ru-1", "ru-2", "ru-3", "ru-6", "ru-7", "ru-8", "ru-9"]


BASE_DIR = Path(__file__).resolve().parent
WHITELIST_FILE = BASE_DIR / "ipwhitelist_safe_cidr.txt"
LOG_FILE = Path(os.getenv("LOG_FILE", str(BASE_DIR / "finder.log")).strip() or str(BASE_DIR / "finder.log"))
DASHBOARD_STATIC_DIR = BASE_DIR / "dashboard"


def required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is not set in .env")
    return value


def optional_env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def int_env(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc

    if value < minimum:
        raise RuntimeError(f"{name} must be >= {minimum}")

    return value


def bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default

    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def list_env(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name)
    if not raw:
        return default

    values = [item.strip() for item in raw.split(",") if item.strip()]
    if not values:
        raise RuntimeError(f"{name} must contain at least one region")

    return values


TELEGRAM_BOT_TOKEN = required_env("TELEGRAM_BOT_TOKEN")
TELEGRAM_ALLOWED_CHAT_ID = required_env("TELEGRAM_ALLOWED_CHAT_ID")
SOCKS5_PROXY = optional_env("SOCKS5_PROXY")

OS_AUTH_URL = required_env("OS_AUTH_URL")
OS_PROJECT_ID = optional_env("OS_PROJECT_ID")
OS_PROJECT_NAME = optional_env("OS_PROJECT_NAME")
OS_USERNAME = required_env("OS_USERNAME")
OS_PASSWORD = required_env("OS_PASSWORD")
OS_USER_DOMAIN_NAME = optional_env("OS_USER_DOMAIN_NAME", "Default")
OS_PROJECT_DOMAIN_NAME = optional_env("OS_PROJECT_DOMAIN_NAME", "Default")
OS_INTERFACE = optional_env("OS_INTERFACE", "public")
OS_IDENTITY_API_VERSION = optional_env("OS_IDENTITY_API_VERSION", "3")
OS_COMPUTE_API_VERSION = optional_env("OS_COMPUTE_API_VERSION", "2.72")

if not OS_PROJECT_ID and not OS_PROJECT_NAME:
    raise RuntimeError("OS_PROJECT_ID or OS_PROJECT_NAME must be set in .env")


def openstack_no_proxy_value() -> str:
    values = [
        item.strip()
        for item in optional_env("OPENSTACK_NO_PROXY", "127.0.0.1,localhost").split(",")
        if item.strip()
    ]
    existing = {item.lower() for item in values}
    for required in ("127.0.0.1", "localhost"):
        if required not in existing:
            values.append(required)
    return ",".join(values)


def configure_openstack_proxy():
    proxy = optional_env("OPENSTACK_PROXY")
    fallback = bool_env("OPENSTACK_PROXY_FALLBACK_TO_SOCKS5_PROXY", True)

    if not proxy and fallback:
        proxy = SOCKS5_PROXY

    if not proxy:
        print("OpenStack proxy: direct", flush=True)
        return

    no_proxy = openstack_no_proxy_value()
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
        os.environ[name] = proxy
    os.environ["NO_PROXY"] = no_proxy
    os.environ["no_proxy"] = no_proxy

    print("OpenStack proxy: enabled", flush=True)

TARGET_COUNT = int_env("TARGET_COUNT", 11)
GOOD_IP_SYNC_INTERVAL = int_env("GOOD_IP_SYNC_INTERVAL", 300)
WHITELIST_MAX_BYTES = int_env("WHITELIST_MAX_BYTES", 1024 * 1024)
REGIONS = list_env("REGIONS", DEFAULT_REGIONS)
FLOATING_NETWORK_ID = optional_env("FLOATING_NETWORK_ID")
FLOATING_NETWORK_NAME = optional_env("FLOATING_NETWORK_NAME")

PROVISION_ENABLED = bool_env("PROVISION_ENABLED", False)
PROVISION_ORIGIN_IP = optional_env("PROVISION_ORIGIN_IP")
PROVISION_VLESS_TEMPLATE = optional_env("PROVISION_VLESS_TEMPLATE")
PROVISION_PREEMPTIBLE_REGIONS = list_env("PROVISION_PREEMPTIBLE_REGIONS", ["ru-1", "ru-3", "ru-7", "ru-8"])
PROVISION_ALLOW_NON_PREEMPTIBLE = bool_env("PROVISION_ALLOW_NON_PREEMPTIBLE", False)
PROVISION_SERVER_NAME_PREFIX = optional_env("PROVISION_SERVER_NAME_PREFIX", "selectel-finder")
PROVISION_IMAGE_ID = optional_env("PROVISION_IMAGE_ID")
PROVISION_IMAGE_NAME = optional_env("PROVISION_IMAGE_NAME", "Ubuntu 24.04 LTS 64-bit")
PROVISION_FLAVOR_ID = optional_env("PROVISION_FLAVOR_ID")
PROVISION_FLAVOR_NAME = optional_env("PROVISION_FLAVOR_NAME")
PROVISION_REQUIRE_LOCAL_DISK = bool_env("PROVISION_REQUIRE_LOCAL_DISK", True)
PROVISION_NETWORK_ID = optional_env("PROVISION_NETWORK_ID")
PROVISION_NETWORK_NAME = optional_env("PROVISION_NETWORK_NAME")
PROVISION_SECURITY_GROUP = optional_env("PROVISION_SECURITY_GROUP", "selectel-finder-proxy")
PROVISION_KEY_NAME = optional_env("PROVISION_KEY_NAME")
PROVISION_AVAILABILITY_ZONE = optional_env("PROVISION_AVAILABILITY_ZONE")
PROVISION_AUTO_FLAVOR_FALLBACK = bool_env("PROVISION_AUTO_FLAVOR_FALLBACK", True)
PROVISION_MAX_FLAVOR_ATTEMPTS = int_env("PROVISION_MAX_FLAVOR_ATTEMPTS", 10)
PROVISION_SERVER_WAIT_SECONDS = int_env("PROVISION_SERVER_WAIT_SECONDS", 300)
PROVISION_SETUP_WAIT_SECONDS = int_env("PROVISION_SETUP_WAIT_SECONDS", 120, minimum=0)
PROVISION_TCP_CHECK_ENABLED = bool_env("PROVISION_TCP_CHECK_ENABLED", True)
PROVISION_TCP_CHECK_TIMEOUT = int_env("PROVISION_TCP_CHECK_TIMEOUT", 5)
PROVISION_TCP_CHECK_RETRIES = int_env("PROVISION_TCP_CHECK_RETRIES", 6)
PROVISION_DECISION_TIMEOUT = int_env("PROVISION_DECISION_TIMEOUT", 300)
PROVISION_DELETE_SERVER_AFTER_RESULT = bool_env("PROVISION_DELETE_SERVER_AFTER_RESULT", True)
PROVISION_DELETE_FAILED_FLOATING_IP = bool_env("PROVISION_DELETE_FAILED_FLOATING_IP", True)

TESTER_API_ENABLED = bool_env("TESTER_API_ENABLED", True)
TESTER_API_HOST = optional_env("TESTER_API_HOST", "0.0.0.0")
TESTER_API_PORT = int_env("TESTER_API_PORT", 8787)
TESTER_TOKEN = optional_env("TESTER_TOKEN")
TESTER_BATCH_SIZE = int_env("TESTER_BATCH_SIZE", 11)
TESTER_LEASE_SECONDS = int_env("TESTER_LEASE_SECONDS", 900)
TESTER_MAX_ATTEMPTS = int_env("TESTER_MAX_ATTEMPTS", 2)
_vless_queue_db_raw = optional_env("VLESS_QUEUE_DB")
VLESS_QUEUE_DB = Path(_vless_queue_db_raw or str(BASE_DIR / "vless_tests.sqlite3"))
configure_vless_queue(VLESS_QUEUE_DB)

DASHBOARD_ENABLED = bool_env("DASHBOARD_ENABLED", True)
DASHBOARD_USERNAME = optional_env("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASSWORD = optional_env("DASHBOARD_PASSWORD")
DASHBOARD_LOG_LINES = int_env("DASHBOARD_LOG_LINES", 200)

running = False
last_good_ip_sync = 0.0
settings_version = 0
settings_lock = threading.RLock()
selected_regions = REGIONS.copy()
waiting_for_whitelist_file = False
provisioning_running = False
provisioning_lock = threading.RLock()
pending_vless_tests = {}
tester_api_server = None
finder_state_lock = threading.RLock()
finder_state = {
    "current_attempt": 0,
    "current_region": "",
    "last_ip": "",
    "last_error": "",
    "started_at": "",
}


def update_finder_state(**kwargs):
    with finder_state_lock:
        finder_state.update(kwargs)


def get_finder_state() -> dict:
    with finder_state_lock:
        return dict(finder_state)


# =========================
# TELEGRAM
# =========================

if SOCKS5_PROXY:
    telebot.apihelper.proxy = {
        "https": SOCKS5_PROXY
    }

setup_file_logging()
configure_openstack_proxy()

bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)


SENSITIVE_ENV_NAMES = [
    "TELEGRAM_BOT_TOKEN",
    "SOCKS5_PROXY",
    "OPENSTACK_PROXY",
    "TESTER_TOKEN",
    "CONTROL_VLESS",
    "OS_PASSWORD",
    "DASHBOARD_PASSWORD",
    "PROVISION_VLESS_TEMPLATE",
]


def redact_text(value) -> str:
    text = str(value or "")
    for name in SENSITIVE_ENV_NAMES:
        secret = os.getenv(name, "").strip()
        if secret and len(secret) >= 4:
            text = text.replace(secret, f"[REDACTED:{name}]")
    text = re.sub(r"vless://\S+", "vless://[REDACTED]", text)
    text = re.sub(r"(?i)(token|password|passwd|secret)=([^&\s]+)", r"\1=[REDACTED]", text)
    return text


configure_vless_queue(redactor=redact_text)


def allowed(message) -> bool:
    return str(message.chat.id) == str(TELEGRAM_ALLOWED_CHAT_ID)


def send(chat_id, text, reply_markup=None):
    try:
        bot.send_message(chat_id, redact_text(text), reply_markup=reply_markup)
    except Exception as e:
        print(f"Telegram send error: {e}", flush=True)


def bump_settings_version() -> int:
    global settings_version

    settings_version += 1
    return settings_version


def get_settings_version() -> int:
    with settings_lock:
        return settings_version


def get_selected_regions() -> list[str]:
    try:
        regions = get_runtime_setting("SELECTED_REGIONS")
        if regions:
            return list(regions)
    except Exception:
        pass

    with settings_lock:
        return selected_regions.copy()


def set_selected_regions(regions: list[str]):
    global selected_regions

    invalid = [region for region in regions if region not in REGIONS]
    if invalid:
        raise RuntimeError(f"Unknown regions: {', '.join(invalid)}")

    unique_regions = []
    for region in regions:
        if region not in unique_regions:
            unique_regions.append(region)

    if not unique_regions:
        raise RuntimeError("At least one region must be selected")

    with settings_lock:
        selected_regions = unique_regions
        bump_settings_version()

    try:
        set_runtime_setting("SELECTED_REGIONS", unique_regions)
    except Exception as e:
        print(f"Failed to persist selected regions: {e}", flush=True)


def set_waiting_for_whitelist_file(value: bool):
    global waiting_for_whitelist_file

    with settings_lock:
        waiting_for_whitelist_file = value


def is_waiting_for_whitelist_file() -> bool:
    with settings_lock:
        return waiting_for_whitelist_file


def format_regions() -> str:
    regions = get_selected_regions()
    return ", ".join(regions)


def region_keyboard():
    selected = set(get_selected_regions())
    keyboard = types.InlineKeyboardMarkup(row_width=3)

    buttons = [
        types.InlineKeyboardButton(
            f"{'✅' if region in selected else '▫️'} {region}",
            callback_data=f"region:toggle:{region}",
        )
        for region in REGIONS
    ]

    keyboard.add(*buttons)
    keyboard.add(
        types.InlineKeyboardButton("Все регионы", callback_data="region:all"),
        types.InlineKeyboardButton("Готово", callback_data="region:done"),
    )
    return keyboard


def create_servers_keyboard():
    keyboard = types.InlineKeyboardMarkup(row_width=1)
    keyboard.add(
        types.InlineKeyboardButton(
            "🚀 Создать серверы и выдать ключи",
            callback_data="provision:start",
        )
    )
    return keyboard


def regions_text() -> str:
    return (
        "🌍 Регионы поиска\n"
        f"Выбрано: {format_regions()}\n\n"
        "Нажимай на регион, чтобы включить или выключить его."
    )


def help_text() -> str:
    return (
        "Команды:\n"
        "/start — запустить поиск\n"
        "/stop — остановить поиск\n"
        "/status — статус, текущая попытка и настройки\n"
        "/test_status — очередь авто-тестера VLESS\n"
        "/test_stop — поставить на паузу создание серверов и выдачу задач телефону\n"
        "/test_start — возобновить создание серверов и выдачу задач телефону\n"
        "/log — показать последние логи\n"
        "/create_servers — создать серверы и выдать ключи из найденных IP\n"
        "/upload — загрузить файл с IP/CIDR\n"
        "/cancel — отменить ожидание файла\n"
        "/regions — выбрать регионы\n"
        "/sync — сверить найденные IP с OpenStack\n\n"
        "После /upload отправь .txt файл с IP или CIDR, по одному в строке."
    )


def start_finder(actor: str = "telegram") -> dict:
    global running, last_good_ip_sync

    if running:
        return {"ok": True, "started": False, "status": "already_running", "message": "✅ Поиск уже запущен"}

    networks = load_whitelist()

    approved, existing_candidates, left_to_find = remaining_ips_to_find(networks)
    current_target = target_count()
    candidate_slots = current_target - approved

    if approved >= current_target:
        return {
            "ok": True,
            "started": False,
            "status": "target_ready",
            "approved": approved,
            "target": current_target,
            "message": f"✅ Уже есть {approved}/{current_target} рабочих ключей. Добор не нужен.",
        }

    if left_to_find <= 0:
        return {
            "ok": True,
            "started": False,
            "status": "candidates_ready",
            "approved": approved,
            "target": current_target,
            "existing_candidates": existing_candidates,
            "candidate_slots": candidate_slots,
            "left_to_find": left_to_find,
            "message": (
                "✅ Кандидаты уже набраны. Поиск не нужен.\n"
                f"✅ Принято ключей: {approved}/{current_target}\n"
                f"📦 Найдено кандидатов: {existing_candidates}/{candidate_slots}"
            ),
        }

    if not get_selected_regions():
        raise RuntimeError("Не выбран ни один регион")

    last_good_ip_sync = 0
    running = True
    update_finder_state(current_attempt=0, current_region="", last_ip="", last_error="", started_at=time.strftime("%Y-%m-%d %H:%M:%S"))
    result = {
        "ok": True,
        "started": True,
        "status": "started",
        "whitelist_count": len(networks),
        "approved": approved,
        "target": current_target,
        "existing_candidates": existing_candidates,
        "candidate_slots": candidate_slots,
        "left_to_find": left_to_find,
        "regions": get_selected_regions(),
        "message": (
            "🚀 Поиск IP запущен\n"
            f"🎯 Целей: {len(networks)}\n"
            f"✅ Принято ключей: {approved}/{current_target}\n"
            f"📦 Уже найдено кандидатов: {existing_candidates}/{candidate_slots}\n"
            f"🔎 Осталось найти IP: {left_to_find}\n"
            f"🌍 Регионы: {format_regions()}"
        ),
    }
    audit_log("finder_start", "", result, actor=actor)
    return result


def stop_finder(actor: str = "telegram") -> dict:
    global running

    was_running = running
    auto_was_enabled = is_full_auto_mode_enabled()
    if auto_was_enabled:
        set_full_auto_mode(False)
    running = False
    result = {
        "ok": True,
        "stopped": was_running,
        "status": "stopped" if was_running else "already_stopped",
        "auto_mode_disabled": auto_was_enabled,
        "message": (
            "⏸ Поиск IP остановлен, авто-режим выключен"
            if auto_was_enabled
            else ("⏸ Поиск IP остановлен" if was_running else "ℹ️ Поиск IP уже остановлен")
        ),
    }
    audit_log("finder_stop", "", result, actor=actor)
    return result


# =========================
# FILES
# =========================

def parse_whitelist_text(text: str):
    networks = []
    invalid = []
    seen = set()

    for line_number, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()

        for token in re.split(r"[\s,;]+", line):
            if not token:
                continue

            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError:
                invalid.append((line_number, token))
                continue

            key = str(network)
            if key in seen:
                continue

            networks.append(network)
            seen.add(key)

    return networks, invalid


def load_whitelist():
    if not WHITELIST_FILE.exists():
        raise RuntimeError(f"Whitelist file not found: {WHITELIST_FILE}")

    text = WHITELIST_FILE.read_text(encoding="utf-8-sig")
    networks, invalid = parse_whitelist_text(text)

    for line_number, token in invalid:
        print(f"⚠️ Bad CIDR skipped on line {line_number}: {token}", flush=True)

    if not networks:
        raise RuntimeError(f"Whitelist is empty: {WHITELIST_FILE}")

    print(f"✅ Загружено CIDR: {len(networks)}", flush=True)
    return networks


def save_whitelist_networks(networks):
    temp_file = WHITELIST_FILE.with_suffix(".tmp")

    with open(temp_file, "w", encoding="utf-8") as f:
        for network in networks:
            f.write(f"{network}\n")

    temp_file.replace(WHITELIST_FILE)


def save_whitelist_from_bytes(data: bytes) -> int:
    if len(data) > WHITELIST_MAX_BYTES:
        raise RuntimeError(f"Файл слишком большой. Максимум: {WHITELIST_MAX_BYTES} bytes")

    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise RuntimeError("Файл должен быть в UTF-8") from exc

    networks, invalid = parse_whitelist_text(text)

    if invalid:
        preview = ", ".join(f"line {line}: {token}" for line, token in invalid[:5])
        raise RuntimeError(f"В файле есть некорректные IP/CIDR: {preview}")

    if not networks:
        raise RuntimeError("В файле нет IP или CIDR")

    save_whitelist_networks(networks)

    with settings_lock:
        bump_settings_version()

    return len(networks)


def ip_allowed(ip, networks) -> bool:
    ip_obj = ipaddress.ip_address(ip)
    return any(ip_obj in net for net in networks)


@dataclass
class PendingVlessTest:
    token: str
    record: GoodIpRecord
    server_id: str
    vless_key: str
    event: threading.Event = field(default_factory=threading.Event)
    result: str = ""


def save_managed_list(name: str, content: str, actor: str = "dashboard") -> dict:
    result = save_managed_list_file(name, content)
    if result["name"] == "ipwhitelist_safe_cidr.txt":
        with settings_lock:
            bump_settings_version()
    audit_log("list_update", result["name"], {"bytes": result["bytes"], "lines": result["lines"]}, actor=actor)
    return result


def approved_count() -> int:
    return len(load_approved_ips())


def remaining_slots() -> int:
    """How many approved keys are still needed to reach TARGET_COUNT."""
    return max(target_count() - approved_count(), 0)


def remaining_ips_to_find(networks=None) -> tuple[int, int, int]:
    """Return (approved, candidates, left_to_find).

    TARGET_COUNT is the final number of working keys.
    good_ips.txt contains candidates that have already been found but not yet checked.
    Therefore finder should search only: TARGET_COUNT - approved - candidates.
    """
    approved = approved_count()
    candidates = count_matching_good_ips(networks, exclude_approved=True)
    left_to_find = max(target_count() - approved - candidates, 0)
    return approved, candidates, left_to_find


def count_good_ips() -> int:
    return len(load_good_ips())


def count_matching_good_ips(networks=None, exclude_approved=False) -> int:
    records = load_good_ips()
    banned = load_banned_ips()
    approved = load_approved_ips() if exclude_approved else set()
    blocking = load_blocking_vless_ips()
    if networks is None:
        return len(
            [
                record
                for record in records
                if not ip_in_banned_networks(record.ip, banned)
                and record.ip not in approved
                and record.ip not in blocking
            ]
        )

    return len(
        [
            record
            for record in records
            if not ip_in_banned_networks(record.ip, banned)
            and record.ip not in approved
            and record.ip not in blocking
            and ip_allowed(record.ip, networks)
        ]
    )


# =========================
# OPENSTACK
# =========================

def region_env(name: str, region: str) -> str:
    suffix = region.upper().replace("-", "_")
    return optional_env(f"{name}_{suffix}")


def openstack_config() -> OpenStackConfig:
    return OpenStackConfig(
        auth_url=OS_AUTH_URL,
        project_id=OS_PROJECT_ID,
        project_name=OS_PROJECT_NAME,
        username=OS_USERNAME,
        password=OS_PASSWORD,
        user_domain_name=OS_USER_DOMAIN_NAME,
        project_domain_name=OS_PROJECT_DOMAIN_NAME,
        interface=OS_INTERFACE,
        identity_api_version=OS_IDENTITY_API_VERSION,
        compute_api_version=OS_COMPUTE_API_VERSION,
    )


def selectel_cloud_config() -> SelectelCloudConfig:
    return SelectelCloudConfig(
        floating_network_id=FLOATING_NETWORK_ID,
        floating_network_name=FLOATING_NETWORK_NAME,
        provision_origin_ip=PROVISION_ORIGIN_IP,
        provision_vless_template=PROVISION_VLESS_TEMPLATE,
        provision_preemptible_regions=provision_preemptible_regions(),
        provision_server_name_prefix=PROVISION_SERVER_NAME_PREFIX,
        provision_image_id=PROVISION_IMAGE_ID,
        provision_image_name=PROVISION_IMAGE_NAME,
        provision_flavor_id=PROVISION_FLAVOR_ID,
        provision_flavor_name=PROVISION_FLAVOR_NAME,
        provision_require_local_disk=PROVISION_REQUIRE_LOCAL_DISK,
        provision_network_id=PROVISION_NETWORK_ID,
        provision_network_name=PROVISION_NETWORK_NAME,
        provision_security_group=PROVISION_SECURITY_GROUP,
        provision_key_name=PROVISION_KEY_NAME,
        provision_availability_zone=PROVISION_AVAILABILITY_ZONE,
        provision_auto_flavor_fallback=PROVISION_AUTO_FLAVOR_FALLBACK,
        provision_max_flavor_attempts=provision_max_flavor_attempts(),
        provision_server_wait_seconds=provision_server_wait_seconds(),
        provision_setup_wait_seconds=provision_setup_wait_seconds(),
        provision_tcp_check_enabled=provision_tcp_check_enabled(),
        provision_tcp_check_timeout=provision_tcp_check_timeout(),
        provision_tcp_check_retries=provision_tcp_check_retries(),
        region_env=region_env,
    )


def get_connection(region):
    return cloud_get_connection(openstack_config(), region)


def close_connection(conn):
    return cloud_close_connection(conn)


def get_floating_network(conn, region):
    return cloud_get_floating_network(conn, region, selectel_cloud_config())


def create_floating_ip(region):
    return cloud_create_floating_ip(region, openstack_config(), selectel_cloud_config())


def delete_floating_ip(conn, ip_id) -> bool:
    return cloud_delete_floating_ip(conn, ip_id)


def saved_ip_active(record: GoodIpRecord) -> bool:
    return cloud_saved_ip_active(record, openstack_config())


def sync_good_ips(networks=None, exclude_approved=False) -> int:
    records = load_good_ips()
    if not records:
        return 0

    active_records = []
    matching_count = 0
    banned = load_banned_ips()
    approved = load_approved_ips() if exclude_approved else set()
    blocking = load_blocking_vless_ips()

    for record in records:
        if ip_in_banned_networks(record.ip, banned):
            print(f"⚠️ Удаляю забаненную запись good_ips.txt: {record.ip}", flush=True)
            continue

        if saved_ip_active(record):
            active_records.append(record)
            if record.ip not in approved and record.ip not in blocking and (networks is None or ip_allowed(record.ip, networks)):
                matching_count += 1
        else:
            print(f"⚠️ Удаляю устаревшую запись good_ips.txt: {record.ip}", flush=True)

    if len(active_records) != len(records):
        write_good_ips(active_records)

    return matching_count


def matching_good_ip_records(networks=None, exclude_approved=False) -> list[GoodIpRecord]:
    banned = load_banned_ips()
    approved = load_approved_ips() if exclude_approved else set()
    blocking = load_blocking_vless_ips()
    records = []

    for record in load_good_ips():
        if ip_in_banned_networks(record.ip, banned):
            continue
        if record.ip in approved:
            continue
        if record.ip in blocking:
            continue
        if networks is not None and not ip_allowed(record.ip, networks):
            continue
        records.append(record)

    return records


# =========================
# RUNTIME SETTINGS
# =========================

RUNTIME_SETTING_PREFIX = "setting:"
RUNTIME_SETTING_SPECS = [
    {
        "key": "TARGET_COUNT",
        "group": "Поиск IP",
        "label": "Цель рабочих ключей",
        "kind": "int",
        "default": TARGET_COUNT,
        "min": 1,
        "max": 200,
    },
    {
        "key": "SELECTED_REGIONS",
        "group": "Поиск IP",
        "label": "Регионы поиска",
        "kind": "regions",
        "default": REGIONS,
        "choices": REGIONS,
    },
    {
        "key": "GOOD_IP_SYNC_INTERVAL",
        "group": "Поиск IP",
        "label": "Интервал синхронизации good IP, сек",
        "kind": "int",
        "default": GOOD_IP_SYNC_INTERVAL,
        "min": 10,
        "max": 86400,
    },
    {
        "key": "PROVISION_PREEMPTIBLE_REGIONS",
        "group": "Создание серверов",
        "label": "Регионы с preemptible",
        "kind": "regions",
        "default": PROVISION_PREEMPTIBLE_REGIONS,
        "choices": DEFAULT_REGIONS,
    },
    {
        "key": "PROVISION_ALLOW_NON_PREEMPTIBLE",
        "group": "Создание серверов",
        "label": "Разрешить обычные серверы",
        "kind": "bool",
        "default": PROVISION_ALLOW_NON_PREEMPTIBLE,
    },
    {
        "key": "PROVISION_SETUP_WAIT_SECONDS",
        "group": "Создание серверов",
        "label": "Ожидание cloud-init/forwarding, сек",
        "kind": "int",
        "default": PROVISION_SETUP_WAIT_SECONDS,
        "min": 0,
        "max": 3600,
    },
    {
        "key": "PROVISION_SERVER_WAIT_SECONDS",
        "group": "Создание серверов",
        "label": "Ожидание создания сервера, сек",
        "kind": "int",
        "default": PROVISION_SERVER_WAIT_SECONDS,
        "min": 30,
        "max": 3600,
    },
    {
        "key": "PROVISION_MAX_FLAVOR_ATTEMPTS",
        "group": "Создание серверов",
        "label": "Максимум попыток подбора типа сервера",
        "kind": "int",
        "default": PROVISION_MAX_FLAVOR_ATTEMPTS,
        "min": 1,
        "max": 100,
    },
    {
        "key": "PROVISION_TCP_CHECK_ENABLED",
        "group": "Проверка TCP",
        "label": "Проверять TCP/443 с VPS",
        "kind": "bool",
        "default": PROVISION_TCP_CHECK_ENABLED,
    },
    {
        "key": "PROVISION_TCP_CHECK_TIMEOUT",
        "group": "Проверка TCP",
        "label": "Таймаут TCP, сек",
        "kind": "int",
        "default": PROVISION_TCP_CHECK_TIMEOUT,
        "min": 1,
        "max": 120,
    },
    {
        "key": "PROVISION_TCP_CHECK_RETRIES",
        "group": "Проверка TCP",
        "label": "Повторы TCP",
        "kind": "int",
        "default": PROVISION_TCP_CHECK_RETRIES,
        "min": 1,
        "max": 300,
    },
    {
        "key": "PROVISION_DELETE_SERVER_AFTER_RESULT",
        "group": "Очистка",
        "label": "Удалять временный сервер после результата",
        "kind": "bool",
        "default": PROVISION_DELETE_SERVER_AFTER_RESULT,
    },
    {
        "key": "PROVISION_DELETE_FAILED_FLOATING_IP",
        "group": "Очистка",
        "label": "Удалять Floating IP при ошибке создания",
        "kind": "bool",
        "default": PROVISION_DELETE_FAILED_FLOATING_IP,
    },
    {
        "key": "TESTER_BATCH_SIZE",
        "group": "Телефон",
        "label": "Размер пачки задач",
        "kind": "int",
        "default": TESTER_BATCH_SIZE,
        "min": 1,
        "max": 100,
    },
    {
        "key": "TESTER_LEASE_SECONDS",
        "group": "Телефон",
        "label": "Время аренды задачи, сек",
        "kind": "int",
        "default": TESTER_LEASE_SECONDS,
        "min": 30,
        "max": 86400,
    },
    {
        "key": "TESTER_MAX_ATTEMPTS",
        "group": "Телефон",
        "label": "Максимум попыток телефона",
        "kind": "int",
        "default": TESTER_MAX_ATTEMPTS,
        "min": 1,
        "max": 20,
    },
]
RUNTIME_SETTING_BY_KEY = {spec["key"]: spec for spec in RUNTIME_SETTING_SPECS}


def setting_default_value(spec: dict):
    value = spec["default"]
    if spec["kind"] == "regions":
        return list(value)
    return value


def normalize_bool_setting(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    raw = str(value).strip().lower()
    if raw in {"1", "true", "yes", "y", "on"}:
        return "true"
    if raw in {"0", "false", "no", "n", "off"}:
        return "false"
    raise RuntimeError("value must be true or false")


def normalize_int_setting(spec: dict, value) -> str:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("value must be an integer") from exc
    minimum = int(spec.get("min", 0))
    maximum = int(spec.get("max", 10**9))
    if parsed < minimum or parsed > maximum:
        raise RuntimeError(f"value must be between {minimum} and {maximum}")
    return str(parsed)


def normalize_regions_setting(spec: dict, value) -> str:
    if isinstance(value, str):
        regions = [item.strip() for item in value.split(",") if item.strip()]
    elif isinstance(value, list):
        regions = [str(item).strip() for item in value if str(item).strip()]
    else:
        raise RuntimeError("value must be a comma-separated string or list")

    choices = list(spec.get("choices") or DEFAULT_REGIONS)
    invalid = [region for region in regions if region not in choices]
    if invalid:
        raise RuntimeError(f"unknown regions: {', '.join(invalid)}")

    unique = []
    for region in regions:
        if region not in unique:
            unique.append(region)
    if not unique:
        raise RuntimeError("at least one region must be selected")
    return ",".join(unique)


def normalize_runtime_setting(key: str, value) -> str:
    spec = RUNTIME_SETTING_BY_KEY.get(key)
    if not spec:
        raise RuntimeError(f"unknown setting: {key}")
    kind = spec["kind"]
    if kind == "bool":
        return normalize_bool_setting(value)
    if kind == "int":
        return normalize_int_setting(spec, value)
    if kind == "regions":
        return normalize_regions_setting(spec, value)
    raise RuntimeError(f"unsupported setting kind: {kind}")


def parse_runtime_setting(spec: dict, raw: str):
    if spec["kind"] == "bool":
        return raw == "true"
    if spec["kind"] == "int":
        return int(raw)
    if spec["kind"] == "regions":
        return [item.strip() for item in raw.split(",") if item.strip()]
    return raw


def get_runtime_setting_raw(key: str) -> str | None:
    return get_tester_control_raw(RUNTIME_SETTING_PREFIX + key)


def get_runtime_setting(key: str):
    spec = RUNTIME_SETTING_BY_KEY[key]
    raw = get_runtime_setting_raw(key)
    if raw is None:
        return setting_default_value(spec)
    try:
        return parse_runtime_setting(spec, raw)
    except Exception:
        return setting_default_value(spec)


def set_runtime_setting(key: str, value):
    normalized = normalize_runtime_setting(key, value)
    set_tester_control_value(RUNTIME_SETTING_PREFIX + key, normalized)
    if key == "SELECTED_REGIONS":
        with settings_lock:
            selected_regions[:] = parse_runtime_setting(RUNTIME_SETTING_BY_KEY[key], normalized)
            bump_settings_version()
    return get_runtime_setting(key)


def reset_runtime_setting(key: str):
    if key not in RUNTIME_SETTING_BY_KEY:
        raise RuntimeError(f"unknown setting: {key}")
    delete_tester_control_value(RUNTIME_SETTING_PREFIX + key)
    if key == "SELECTED_REGIONS":
        with settings_lock:
            selected_regions[:] = REGIONS.copy()
            bump_settings_version()


def runtime_settings_snapshot() -> list[dict]:
    items = []
    for spec in RUNTIME_SETTING_SPECS:
        key = spec["key"]
        raw = get_runtime_setting_raw(key)
        current = get_runtime_setting(key)
        default = setting_default_value(spec)
        item = {
            "key": key,
            "group": spec["group"],
            "label": spec["label"],
            "kind": spec["kind"],
            "value": current,
            "default": default,
            "overridden": raw is not None,
        }
        if "min" in spec:
            item["min"] = spec["min"]
        if "max" in spec:
            item["max"] = spec["max"]
        if "choices" in spec:
            item["choices"] = spec["choices"]
        items.append(item)
    return items


RUNTIME_PRESETS = {
    "safe_ru3_ru7": {
        "SELECTED_REGIONS": ["ru-3", "ru-7"],
        "PROVISION_PREEMPTIBLE_REGIONS": ["ru-3", "ru-7"],
        "PROVISION_ALLOW_NON_PREEMPTIBLE": False,
        "PROVISION_DELETE_FAILED_FLOATING_IP": False,
    },
    "fast_test": {
        "PROVISION_SETUP_WAIT_SECONDS": 120,
        "PROVISION_TCP_CHECK_TIMEOUT": 5,
        "PROVISION_TCP_CHECK_RETRIES": 6,
        "TESTER_BATCH_SIZE": 11,
    },
    "reliable_provisioning": {
        "PROVISION_SETUP_WAIT_SECONDS": 720,
        "PROVISION_TCP_CHECK_TIMEOUT": 8,
        "PROVISION_TCP_CHECK_RETRIES": 30,
        "TESTER_LEASE_SECONDS": 900,
    },
    "keep_failed_ip": {
        "PROVISION_DELETE_SERVER_AFTER_RESULT": True,
        "PROVISION_DELETE_FAILED_FLOATING_IP": False,
    },
}


def apply_runtime_preset(name: str, actor: str = "dashboard") -> dict:
    values = RUNTIME_PRESETS.get(name)
    if not values:
        raise RuntimeError(f"unknown preset: {name}")
    before = {key: get_runtime_setting(key) for key in values}
    for key, value in values.items():
        set_runtime_setting(key, value)
    after = {key: get_runtime_setting(key) for key in values}
    audit_log("settings_preset", name, {"before": before, "after": after}, actor=actor)
    return {"ok": True, "preset": name, "settings": runtime_settings_snapshot()}


def update_runtime_settings(payload: dict, actor: str = "dashboard") -> dict:
    reset_keys = payload.get("reset") or []
    values = payload.get("values") or {}
    if not isinstance(reset_keys, list):
        raise RuntimeError("reset must be a list")
    if not isinstance(values, dict):
        raise RuntimeError("values must be an object")

    before = {}
    touched = [str(key) for key in reset_keys] + [str(key) for key in values]
    for key in touched:
        if key in RUNTIME_SETTING_BY_KEY:
            before[key] = get_runtime_setting(key)

    for key in reset_keys:
        reset_runtime_setting(str(key))
    for key, value in values.items():
        set_runtime_setting(str(key), value)

    after = {key: get_runtime_setting(key) for key in before}
    if before:
        audit_log("settings_update", ",".join(before.keys()), {"before": before, "after": after}, actor=actor)

    return {"ok": True, "settings": runtime_settings_snapshot()}


def target_count() -> int:
    return int(get_runtime_setting("TARGET_COUNT"))


def good_ip_sync_interval() -> int:
    return int(get_runtime_setting("GOOD_IP_SYNC_INTERVAL"))


def provision_preemptible_regions() -> list[str]:
    return list(get_runtime_setting("PROVISION_PREEMPTIBLE_REGIONS"))


def provision_allow_non_preemptible() -> bool:
    return bool(get_runtime_setting("PROVISION_ALLOW_NON_PREEMPTIBLE"))


def provision_setup_wait_seconds() -> int:
    return int(get_runtime_setting("PROVISION_SETUP_WAIT_SECONDS"))


def provision_server_wait_seconds() -> int:
    return int(get_runtime_setting("PROVISION_SERVER_WAIT_SECONDS"))


def provision_max_flavor_attempts() -> int:
    return int(get_runtime_setting("PROVISION_MAX_FLAVOR_ATTEMPTS"))


def provision_tcp_check_enabled() -> bool:
    return bool(get_runtime_setting("PROVISION_TCP_CHECK_ENABLED"))


def provision_tcp_check_timeout() -> int:
    return int(get_runtime_setting("PROVISION_TCP_CHECK_TIMEOUT"))


def provision_tcp_check_retries() -> int:
    return int(get_runtime_setting("PROVISION_TCP_CHECK_RETRIES"))


def provision_delete_server_after_result() -> bool:
    return bool(get_runtime_setting("PROVISION_DELETE_SERVER_AFTER_RESULT"))


def provision_delete_failed_floating_ip() -> bool:
    return bool(get_runtime_setting("PROVISION_DELETE_FAILED_FLOATING_IP"))


def tester_batch_size() -> int:
    return int(get_runtime_setting("TESTER_BATCH_SIZE"))


def tester_lease_seconds() -> int:
    return int(get_runtime_setting("TESTER_LEASE_SECONDS"))


def tester_max_attempts() -> int:
    return int(get_runtime_setting("TESTER_MAX_ATTEMPTS"))


def region_provision_block_reason(region: str) -> str:
    return (
        f"Region {region} is not in PROVISION_PREEMPTIBLE_REGIONS and "
        "PROVISION_ALLOW_NON_PREEMPTIBLE=false; IP skipped as not provisionable"
    )


def region_can_provision(region: str) -> bool:
    return region in provision_preemptible_regions() or provision_allow_non_preemptible()


def dashboard_settings_snapshot() -> dict:
    return {"ok": True, "generated_at": now_ts(), "settings": runtime_settings_snapshot()}


def dashboard_static_content(relative_path: str) -> tuple[bytes, str]:
    relative_path = unquote(str(relative_path or "index.html")).replace("\\", "/").lstrip("/")
    target = (DASHBOARD_STATIC_DIR / relative_path).resolve()
    root = DASHBOARD_STATIC_DIR.resolve()
    if target != root and root not in target.parents:
        raise RuntimeError("invalid dashboard path")
    if not target.is_file():
        raise FileNotFoundError(relative_path)

    content_types = {
        ".html": "text/html; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".js": "application/javascript; charset=utf-8",
        ".json": "application/json; charset=utf-8",
        ".txt": "text/plain; charset=utf-8",
        ".svg": "image/svg+xml",
    }
    return target.read_bytes(), content_types.get(target.suffix.lower(), "application/octet-stream")



def classify_phone_failure(error: str) -> str:
    """Map worker error strings into actionable review statuses."""
    e = (error or "").strip().lower()
    if e.startswith("phone_tcp_unreachable") or "phone_tcp_unreachable" in e:
        return "ip_not_suitable"
    if e.startswith("exit_ip_mismatch") or "exit_ip_mismatch" in e:
        return "exit_ip_mismatch"
    if e.startswith("vless_failed") or "curl_through_test_proxy_failed" in e or "cannot complete socks5" in e:
        return "vless_failed"
    return "phone_failed"


def legacy_phone_failure_human_hint(status: str) -> str:
    if status in IP_NOT_SUITABLE_STATUSES:
        return "телефон не смог напрямую открыть TCP к candidate IP:443; IP не подходит как белый входной IP для этой сети"
    if status == "vless_failed":
        return "TCP до candidate IP есть, но VLESS/REALITY/curl через test proxy не сработал"
    if status == "exit_ip_mismatch":
        return "VLESS отвечает, но exit IP не совпал с выбранной политикой проверки"
    return "телефонная проверка не прошла"


def phone_failure_human_hint(status: str) -> str:
    if status in IP_NOT_SUITABLE_STATUSES:
        return "IP не подходит: с телефона не открывается TCP/443 к candidate IP, значит этот IP не годится как белый входной IP для этой сети"
    if status == "vless_failed":
        return "TCP до candidate IP есть, но VLESS/REALITY/curl через test proxy не сработал"
    if status == "exit_ip_mismatch":
        return "VLESS отвечает, но exit IP не совпал с выбранной политикой проверки"
    return "телефонная проверка не прошла"


def phone_failure_title(status: str) -> str:
    if status in IP_NOT_SUITABLE_STATUSES:
        return "IP не подходит для этой сети"
    return "Авто-тестер не подтвердил IP"


def phone_failure_detail_label(status: str) -> str:
    if status in IP_NOT_SUITABLE_STATUSES:
        return "Диагностика"
    return "Ошибка"


def pause_all_testing():
    set_testing_paused(True)
    set_provisioning_paused(True)


def resume_all_testing():
    set_testing_paused(False)
    set_provisioning_paused(False)


def has_active_vless_test_ip(ip: str) -> bool:
    status = get_vless_status_for_ip(ip)
    return status in ACTIVE_VLESS_STATUSES


def has_blocking_vless_test_ip(ip: str) -> bool:
    """Return True when this IP must not be auto-scheduled again.

    Manual retry from dashboard is still allowed for REVIEW_VLESS_STATUSES.
    """
    status = get_vless_status_for_ip(ip)
    return bool(status and status not in {"deleted", "manual_banned"})


def mark_provision_failed(record: GoodIpRecord, error: str, server_id: str = "", vless_key: str = "") -> int | None:
    vless_key = vless_key or make_vless_key(record.ip)
    return queue_mark_provision_failed(record, error, server_id, vless_key)


def start_manual_retry(test_id: int, actor: str = "dashboard") -> dict:
    row = get_vless_test_by_id(test_id)
    if not row:
        raise RuntimeError("test not found")
    status = row.get("status") or ""
    if status not in REVIEW_VLESS_STATUSES:
        raise RuntimeError(f"retry is allowed only for failed/review statuses, current status={status}")

    if status in PHONE_FAILURE_STATUSES and row.get("server_id") and row.get("vless_key"):
        result = reset_vless_test_to_queued(test_id)
        audit_log("retry_existing_server", str(test_id), {"status": status}, actor=actor)
        return result

    if is_provisioning_paused():
        raise RuntimeError("server creation is paused; use /test_start first")

    record = GoodIpRecord(ip=row["ip"], region=row["region"], ip_id=row["ip_id"] or "")
    if not region_can_provision(record.region):
        error = region_provision_block_reason(record.region)
        task_id = mark_provision_failed(
            record,
            error,
            server_id=row.get("server_id") or "",
            vless_key=row.get("vless_key") or "",
        )
        cleanup_failed_floating_ip_record_if_enabled(record)
        result = {"id": int(task_id or test_id), "status": "provision_failed", "error": error}
        audit_log("retry_blocked_region", str(test_id), result, actor=actor)
        return result

    mark_test_provisioning(test_id)

    thread = threading.Thread(target=run_single_vless_test, args=(record,), kwargs={"force": True}, daemon=True)
    thread.start()
    result = {"id": int(test_id), "status": "provisioning"}
    audit_log("retry_provisioning", str(test_id), {"region": record.region}, actor=actor)
    return result


def manually_delete_vless_test(test_id: int, actor: str = "dashboard") -> dict:
    row = get_vless_test_by_id(test_id)
    if not row:
        raise RuntimeError("test not found")
    status = row.get("status") or ""
    if status == "approved":
        raise RuntimeError("approved key is not deleted from dashboard")

    record = GoodIpRecord(ip=row["ip"], region=row["region"], ip_id=row["ip_id"] or "")
    server_id = row.get("server_id") or ""
    cleanup_errors = []
    conn = None
    try:
        conn = get_connection(record.region)
        if server_id:
            try:
                cleanup_test_server(conn, server_id, record.ip)
            except Exception as e:
                cleanup_errors.append(f"server cleanup: {e}")
        try:
            if not delete_floating_ip_address(conn, record.ip, record.ip_id):
                cleanup_errors.append("floating ip delete: not confirmed")
        except Exception as e:
            cleanup_errors.append(f"floating ip delete: {e}")
    finally:
        close_connection(conn)

    ban_ip(record.ip, f"manual_dashboard_delete region={record.region}")
    remove_banned_good_ips()
    error_text = "; ".join(cleanup_errors) if cleanup_errors else "manual dashboard delete"
    mark_test_manual_banned(test_id, error_text)

    result = {"id": int(test_id), "status": "manual_banned", "cleanup_errors": cleanup_errors}
    audit_log("delete_ip", str(test_id), {"ip": record.ip, "region": record.region, "status": status, "cleanup_errors": cleanup_errors}, actor=actor)
    return result


def mark_region_tests_provision_failed(region: str, actor: str = "dashboard") -> dict:
    if region not in DEFAULT_REGIONS and region not in REGIONS:
        raise RuntimeError(f"unknown region: {region}")
    error = region_provision_block_reason(region)
    changed = queue_mark_region_tests_provision_failed(region, error)
    result = {"region": region, "changed": changed, "status": "provision_failed"}
    audit_log("bulk_mark_region_provision_failed", region, result, actor=actor)
    return result


def bulk_dashboard_action(payload: dict, actor: str = "dashboard") -> dict:
    action = (payload.get("action") or "").strip().lower()
    limit = max(1, min(int(payload.get("limit") or 100), 300))
    results = []
    errors = []

    if action == "delete_ip_not_suitable":
        ids = select_test_ids(statuses=sorted(IP_NOT_SUITABLE_STATUSES), limit=limit)
        for test_id in ids:
            try:
                results.append(manually_delete_vless_test(test_id, actor=actor))
            except Exception as e:
                errors.append({"id": test_id, "error": str(e)})
        audit_log("bulk_delete_ip_not_suitable", "", {"count": len(results), "errors": errors}, actor=actor)
        return {"ok": True, "action": action, "count": len(results), "results": results, "errors": errors}

    if action == "retry_vless_failed":
        ids = select_test_ids(statuses=["vless_failed"], limit=limit)
        for test_id in ids:
            try:
                results.append(start_manual_retry(test_id, actor=actor))
            except Exception as e:
                errors.append({"id": test_id, "error": str(e)})
        audit_log("bulk_retry_vless_failed", "", {"count": len(results), "errors": errors}, actor=actor)
        return {"ok": True, "action": action, "count": len(results), "results": results, "errors": errors}

    if action == "mark_region_provision_failed":
        region = (payload.get("region") or "").strip()
        if not region:
            raise RuntimeError("region is required")
        result = mark_region_tests_provision_failed(region, actor=actor)
        return {"ok": True, "action": action, **result}

    if action == "delete_old_provision_failed":
        days = max(1, min(int(payload.get("days") or 7), 365))
        older_than = now_ts() - days * 86400
        ids = select_test_ids(statuses=["provision_failed"], older_than=older_than, limit=limit)
        for test_id in ids:
            try:
                results.append(manually_delete_vless_test(test_id, actor=actor))
            except Exception as e:
                errors.append({"id": test_id, "error": str(e)})
        audit_log("bulk_delete_old_provision_failed", "", {"days": days, "count": len(results), "errors": errors}, actor=actor)
        return {"ok": True, "action": action, "days": days, "count": len(results), "results": results, "errors": errors}

    if action == "reconcile_dry_run":
        return {"ok": True, "action": action, "result": reconcile_resources(cleanup=False, actor=actor)}

    if action == "cleanup_stale_temp_servers":
        return {"ok": True, "action": action, "result": reconcile_resources(cleanup=True, actor=actor, limit=limit)}

    raise RuntimeError("unknown bulk action")


def region_diagnostics() -> list[dict]:
    good_counts: dict[str, int] = {}
    for record in load_good_ips():
        good_counts[record.region] = good_counts.get(record.region, 0) + 1
    approved_region_counts = load_approved_region_counts()

    by_region: dict[str, dict] = {}
    rows, last_rows = region_status_rows()

    regions = set(DEFAULT_REGIONS) | set(REGIONS) | set(good_counts) | set(approved_region_counts)
    for row in rows:
        regions.add(row["region"])

    for region in sorted(regions):
        statuses = {status: 0 for status in ["approved", "ip_not_suitable", "phone_tcp_unreachable", "vless_failed", "exit_ip_mismatch", "phone_failed", "provision_failed", "manual_banned", "queued", "testing", "provisioning", "error"]}
        by_region[region] = {
            "region": region,
            "selected": region in get_selected_regions(),
            "preemptible": region in provision_preemptible_regions(),
            "can_provision": region_can_provision(region),
            "good_ips": good_counts.get(region, 0),
            "approved_keys": approved_region_counts.get(region, 0),
            "statuses": statuses,
            "last_error": "",
            "last_error_at": 0,
        }

    for row in rows:
        item = by_region.setdefault(row["region"], {"region": row["region"], "statuses": {}})
        item.setdefault("statuses", {})[row["status"]] = int(row["cnt"])

    for item in by_region.values():
        statuses = item["statuses"]
        statuses["ip_not_suitable_total"] = statuses.get("ip_not_suitable", 0) + statuses.get("phone_tcp_unreachable", 0)
        total_finished = sum(
            statuses.get(status, 0)
            for status in ["approved", "ip_not_suitable", "phone_tcp_unreachable", "vless_failed", "exit_ip_mismatch", "phone_failed", "provision_failed", "error"]
        )
        item["success_rate"] = round((statuses.get("approved", 0) / total_finished) * 100, 1) if total_finished else None

    seen_last_error = set()
    for row in last_rows:
        region = row["region"]
        if region in seen_last_error or region not in by_region:
            continue
        by_region[region]["last_error"] = redact_text(row["error"] or "")
        by_region[region]["last_error_at"] = int(row["ts"] or 0)
        seen_last_error.add(region)

    return list(by_region.values())


def reconcile_resources(cleanup: bool = False, actor: str = "dashboard", limit: int = 100) -> dict:
    active_ids = active_server_ids()
    regions = sorted(set(get_selected_regions()) | {record.region for record in load_good_ips()})
    result = {"cleanup": cleanup, "regions": [], "stale_servers": [], "deleted_servers": [], "errors": []}
    deleted = 0

    for region in regions:
        conn = None
        region_item = {"region": region, "temp_servers": 0, "stale_servers": 0}
        try:
            conn = get_connection(region)
            for server in conn.compute.servers():
                server_id = getattr(server, "id", "")
                name = getattr(server, "name", "") or ""
                if not name.startswith(PROVISION_SERVER_NAME_PREFIX):
                    continue
                region_item["temp_servers"] += 1
                stale = bool(server_id and server_id not in active_ids)
                if not stale:
                    continue
                region_item["stale_servers"] += 1
                server_info = {"region": region, "id": server_id, "name": name}
                result["stale_servers"].append(server_info)
                if cleanup and deleted < limit:
                    cleanup_test_server(conn, server_id, "")
                    result["deleted_servers"].append(server_info)
                    deleted += 1
        except Exception as e:
            result["errors"].append({"region": region, "error": str(e)})
        finally:
            close_connection(conn)
        result["regions"].append(region_item)

    audit_log("reconcile_cleanup" if cleanup else "reconcile_dry_run", "", result, actor=actor)
    return result


def reserve_vless_tests(worker: str, limit: int) -> list[dict]:
    return queue_reserve_vless_tests(
        worker=worker,
        limit=limit,
        batch_size=tester_batch_size(),
        max_attempts=tester_max_attempts(),
        lease_seconds=tester_lease_seconds(),
    )


def complete_vless_test_result(result: dict, worker: str = "") -> dict:
    saved = save_vless_test_result(result, worker, classify_phone_failure)
    if not saved.get("saved") or saved.get("already_final"):
        return saved

    test_id = int(saved["id"])
    final_status = saved["status"]
    record = saved["record"]
    server_id = saved.get("server_id") or ""
    vless_key = saved.get("vless_key") or ""
    latency_ms = saved.get("latency_ms")
    error = saved.get("error") or ""

    # File/OpenStack side effects are intentionally outside the SQLite transaction.
    if final_status == "approved":
        conn = None
        try:
            save_approved_key(record, vless_key)
            send(TELEGRAM_ALLOWED_CHAT_ID, f"✅ Авто-тестер принял IP: {record.ip} ({record.region}), {latency_ms or '-'} ms")
            conn = get_connection(record.region)
            if server_id and provision_delete_server_after_result():
                cleanup_test_server(conn, server_id, record.ip)
        except Exception as e:
            print(f"⚠️ Post-approve cleanup failed for {record.ip}: {e}", flush=True)
            send(TELEGRAM_ALLOWED_CHAT_ID, f"⚠️ Cleanup после успешного авто-теста не удался для {record.ip}: {e}")
        finally:
            close_connection(conn)
    else:
        if final_status in IP_NOT_SUITABLE_STATUSES:
            send(
                TELEGRAM_ALLOWED_CHAT_ID,
                "⚠️ IP не подходит для этой сети, автобана нет\n"
                f"ID: {test_id}\n"
                f"IP: {record.ip} ({record.region})\n"
                f"Статус: {final_status}\n"
                f"Диагностика: {error or 'TCP/443 unavailable from phone'}\n"
                f"Что значит: {phone_failure_human_hint(final_status)}\n\n"
                "Решение: dashboard → Удалить IP, если это обычный найденный кандидат; "
                "или Повторить, если есть подозрение на временный сбой.",
            )
            return {"id": test_id, "saved": True, "status": final_status}

        send(
            TELEGRAM_ALLOWED_CHAT_ID,
            "⚠️ Авто-тестер НЕ подтвердил IP, но IP не забанен автоматически\n"
            f"ID: {test_id}\n"
            f"IP: {record.ip} ({record.region})\n"
            f"Статус: {final_status}\n"
            f"Ошибка: {error or 'phone test failed'}\n"
            f"Что значит: {phone_failure_human_hint(final_status)}\n\n"
            "Решение: dashboard → Повторить проверку или Удалить IP."
        )

    return {"id": test_id, "saved": True, "status": final_status}


def tail_file_text(path: Path, lines: int = 200, max_bytes: int = 200_000) -> str:
    try:
        if not path.exists():
            return ""
        data = path.read_bytes()[-max_bytes:]
        text = data.decode("utf-8", errors="replace")
        return redact_text("\n".join(text.splitlines()[-lines:]))
    except Exception as e:
        return f"Не удалось прочитать {path}: {e}"


def ts_to_text(value) -> str:
    try:
        value = int(value or 0)
    except Exception:
        value = 0
    if not value:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))


def dashboard_snapshot() -> dict:
    fs = get_finder_state()
    with provisioning_lock:
        provision_state = "running" if provisioning_running else "idle"
    try:
        if WHITELIST_FILE.exists():
            networks, _invalid = parse_whitelist_text(WHITELIST_FILE.read_text(encoding="utf-8-sig", errors="ignore"))
            whitelist_count = len(networks)
        else:
            whitelist_count = None
    except Exception:
        whitelist_count = None

    return {
        "ok": True,
        "generated_at": now_ts(),
        "finder": {
            "running": running,
            "current_attempt": fs.get("current_attempt") or 0,
            "current_region": fs.get("current_region") or "",
            "last_ip": fs.get("last_ip") or "",
            "last_error": redact_text(fs.get("last_error") or ""),
            "started_at": fs.get("started_at") or "",
            "selected_regions": get_selected_regions(),
        },
        "control": get_tester_control_state(),
        "provisioning": {"state": provision_state},
        "counts": {
            "target": target_count(),
            "approved": approved_count(),
            "candidates": count_good_ips(),
            "banned": len(load_banned_ips()),
            "whitelist": whitelist_count,
        },
        "queue": get_vless_queue_stats(),
        "metrics": dashboard_metrics(),
        "regions": region_diagnostics(),
        "workers": get_worker_statuses(),
        "tests": get_active_vless_tests(limit=80),
        "audit": get_audit_events(limit=20),
        "lists": managed_lists_snapshot(),
        "logs": {
            "finder": tail_file_text(LOG_FILE, DASHBOARD_LOG_LINES),
        },
    }


# =========================
# PROVISIONING
# =========================

def delete_floating_ip_address(conn, address: str, ip_id: str = "") -> bool:
    return cloud_delete_floating_ip_address(conn, address, ip_id)


def cleanup_failed_floating_ip_if_enabled(conn, record: GoodIpRecord):
    if not provision_delete_failed_floating_ip():
        return
    try:
        deleted = delete_floating_ip_address(conn, record.ip, record.ip_id)
        if deleted:
            remove_good_ip(record.ip)
            print(f"Deleted failed floating IP after provisioning failure: {record.ip}", flush=True)
        else:
            print(f"Failed floating IP cleanup did not confirm deletion for {record.ip}", flush=True)
    except Exception as e:
        print(f"Failed to delete floating IP after provisioning failure for {record.ip}: {e}", flush=True)


def cleanup_failed_floating_ip_record_if_enabled(record: GoodIpRecord):
    if not provision_delete_failed_floating_ip():
        return
    conn = None
    try:
        conn = get_connection(record.region)
        cleanup_failed_floating_ip_if_enabled(conn, record)
    except Exception as e:
        print(f"Failed to open connection for failed Floating IP cleanup {record.ip} ({record.region}): {e}", flush=True)
    finally:
        close_connection(conn)


def make_vless_key(ip: str) -> str:
    return cloud_make_vless_key(ip, selectel_cloud_config())


def validate_provision_config():
    return cloud_validate_provision_config(selectel_cloud_config())


def wait_for_tcp_port(host: str, port: int = 443) -> bool:
    return cloud_wait_for_tcp_port(host, selectel_cloud_config(), port=port)


def create_test_server(conn, record: GoodIpRecord):
    if not region_can_provision(record.region):
        raise RuntimeError(region_provision_block_reason(record.region))
    return cloud_create_test_server(conn, record, selectel_cloud_config())


def cleanup_test_server(conn, server_id: str, ip: str):
    return cloud_cleanup_test_server(conn, server_id, ip)


def vless_keyboard(token: str):
    """Legacy manual keyboard kept for compatibility with old callback messages."""
    keyboard = types.InlineKeyboardMarkup(row_width=2)
    keyboard.add(
        types.InlineKeyboardButton("✅ Работает", callback_data=f"vless:ok:{token}"),
        types.InlineKeyboardButton("❌ Не работает", callback_data=f"vless:bad:{token}"),
    )
    return keyboard


def run_single_vless_test(record: GoodIpRecord, force: bool = False):
    """Create the temporary server and enqueue its VLESS key for the phone worker.

    Phone failures are not banned automatically. Failed provisioning is stored as
    provision_failed and can be retried/deleted from the dashboard.
    """
    conn = get_connection(record.region)
    server = None
    vless_key = make_vless_key(record.ip)

    try:
        if not force and has_blocking_vless_test_ip(record.ip):
            print(f"ℹ️ IP уже есть в очереди/на ручном решении авто-теста: {record.ip}", flush=True)
            return

        server = create_test_server(conn, record)
        server_id = getattr(server, "id", "")

        if not wait_for_tcp_port(record.ip, 443):
            error = f"tcp_443_not_open after {provision_tcp_check_retries()} attempts"
            task_id = mark_provision_failed(record, error, server_id=server_id, vless_key=vless_key)
            send(
                TELEGRAM_ALLOWED_CHAT_ID,
                "⚠️ Сервер создан, но TCP/443 не открылся; телефон не получит задачу\n"
                f"ID: {task_id}\n"
                f"IP: {record.ip}\n"
                f"Регион: {record.region}\n"
                "Решение: dashboard → Повторить проверку или Удалить IP.",
            )
            if server_id and provision_delete_server_after_result():
                try:
                    cleanup_test_server(conn, server_id, record.ip)
                except Exception as cleanup_error:
                    print(f"⚠️ Cleanup after TCP check failed for {record.ip}: {cleanup_error}", flush=True)
            cleanup_failed_floating_ip_if_enabled(conn, record)
            return

        task_id = enqueue_vless_test(record, server_id, vless_key, reset_attempts=force)

        send(
            TELEGRAM_ALLOWED_CHAT_ID,
            "📲 VLESS поставлен в очередь авто-тестера\n"
            f"ID: {task_id}\n"
            f"IP: {record.ip}\n"
            f"Регион: {record.region}\n"
            f"Очередь: {format_vless_queue_stats()}",
        )

    except Exception as e:
        server_id = getattr(server, "id", "") if server else ""
        task_id = mark_provision_failed(record, str(e), server_id=server_id, vless_key=vless_key)
        send(
            TELEGRAM_ALLOWED_CHAT_ID,
            "⚠️ Ошибка создания/подготовки VLESS; IP не забанен автоматически\n"
            f"ID: {task_id}\n"
            f"IP: {record.ip} ({record.region})\n"
            f"Ошибка: {e}\n\n"
            "Решение: dashboard → Повторить проверку или Удалить IP.",
        )
        print(f"⚠️ Provisioning/enqueue error for {record.ip}: {e}", flush=True)
        if server_id and provision_delete_server_after_result():
            try:
                cleanup_test_server(conn, server_id, record.ip)
            except Exception as cleanup_error:
                print(f"⚠️ Cleanup after enqueue error failed for {record.ip}: {cleanup_error}", flush=True)
        cleanup_failed_floating_ip_if_enabled(conn, record)
    finally:
        close_connection(conn)


def provisioning_worker(records: list[GoodIpRecord]):
    global provisioning_running

    queued = 0
    try:
        send(TELEGRAM_ALLOWED_CHAT_ID, f"🧪 Создаю серверы и ставлю в очередь авто-тестера: {len(records)} IP")

        for record in records:
            if is_provisioning_paused():
                send(TELEGRAM_ALLOWED_CHAT_ID, "⏸ Создание серверов поставлено на паузу. Новые IP не трогаю.")
                break
            if is_banned_ip(record.ip):
                continue
            before_stats = get_vless_queue_stats()
            before = before_stats.get("queued", 0) + before_stats.get("testing", 0) + before_stats.get("provision_failed", 0)
            run_single_vless_test(record)
            after_stats = get_vless_queue_stats()
            after = after_stats.get("queued", 0) + after_stats.get("testing", 0) + after_stats.get("provision_failed", 0)
            if after > before:
                queued += 1

        send(
            TELEGRAM_ALLOWED_CHAT_ID,
            "✅ Создание серверов завершено\n"
            f"📲 Поставлено/уже было в очереди: {queued}\n"
            f"Очередь: {format_vless_queue_stats()}",
        )
    finally:
        with provisioning_lock:
            provisioning_running = False
        auto_mode_tick(reason="provisioning_finished")


def start_provisioning_if_needed(networks=None):
    global provisioning_running

    if is_provisioning_paused():
        send(TELEGRAM_ALLOWED_CHAT_ID, "⏸ Создание серверов на паузе. Используй /test_start для возобновления.")
        return

    if not PROVISION_ENABLED:
        send(TELEGRAM_ALLOWED_CHAT_ID, "ℹ️ Автопроверка VLESS выключена: PROVISION_ENABLED=false")
        return

    try:
        validate_provision_config()
    except Exception as e:
        send(TELEGRAM_ALLOWED_CHAT_ID, f"⚠️ Автопроверка VLESS не настроена: {e}")
        return

    slots_left = remaining_slots()
    if slots_left <= 0:
        send(TELEGRAM_ALLOWED_CHAT_ID, f"✅ Уже есть {approved_count()}/{target_count()} рабочих ключей")
        return

    records = []
    skipped_regions = 0
    for record in matching_good_ip_records(networks, exclude_approved=True):
        if has_blocking_vless_test_ip(record.ip):
            continue
        if not region_can_provision(record.region):
            mark_provision_failed(record, region_provision_block_reason(record.region))
            cleanup_failed_floating_ip_record_if_enabled(record)
            skipped_regions += 1
            continue
        records.append(record)
        if len(records) >= slots_left:
            break

    if skipped_regions:
        send(
            TELEGRAM_ALLOWED_CHAT_ID,
            f"ℹ️ Пропущено IP из регионов без разрешенного provisioning: {skipped_regions}. "
            "Они помечены как provision_failed без автобана; Floating IP удалены, если включена соответствующая настройка.",
        )

    if not records:
        send(TELEGRAM_ALLOWED_CHAT_ID, "⚠️ Нет подходящих IP для VLESS-проверки или все уже в очереди авто-тестера")
        return

    with provisioning_lock:
        if provisioning_running:
            send(TELEGRAM_ALLOWED_CHAT_ID, "ℹ️ VLESS-проверка уже идет")
            return
        provisioning_running = True

    thread = threading.Thread(target=provisioning_worker, args=(records,), daemon=True)
    thread.start()


def active_vless_queue_count(stats: dict | None = None) -> int:
    stats = stats or get_vless_queue_stats()
    return sum(int(stats.get(status, 0) or 0) for status in ACTIVE_VLESS_STATUSES)


def auto_mode_tick(reason: str = "") -> dict:
    if not is_full_auto_mode_enabled():
        return {"ok": True, "auto_mode": False, "action": "idle"}

    try:
        if running:
            return {"ok": True, "auto_mode": True, "action": "idle", "reason": "finder_running"}

        with provisioning_lock:
            if provisioning_running:
                return {"ok": True, "auto_mode": True, "action": "idle", "reason": "provisioning_running"}

        stats = get_vless_queue_stats()
        active_tests = active_vless_queue_count(stats)
        if active_tests:
            return {
                "ok": True,
                "auto_mode": True,
                "action": "idle",
                "reason": "tests_active",
                "active_tests": active_tests,
            }

        slots_left = remaining_slots()
        if slots_left <= 0:
            return {"ok": True, "auto_mode": True, "action": "idle", "reason": "target_ready"}

        networks = load_whitelist()
        candidates = count_matching_good_ips(networks, exclude_approved=True)
        if candidates >= slots_left and candidates > 0:
            send(
                TELEGRAM_ALLOWED_CHAT_ID,
                "🤖 Авто-режим: кандидаты набраны, запускаю создание серверов\n"
                f"📦 Кандидатов: {candidates}/{slots_left}\n"
                f"Причина: {reason or '-'}",
            )
            audit_log(
                "auto_start_provisioning",
                "",
                {"reason": reason, "candidates": candidates, "slots_left": slots_left},
                actor="auto",
            )
            start_provisioning_if_needed(networks)
            return {
                "ok": True,
                "auto_mode": True,
                "action": "start_provisioning",
                "candidates": candidates,
                "slots_left": slots_left,
            }

        result = start_finder(actor="auto")
        if result.get("status") == "candidates_ready":
            send(
                TELEGRAM_ALLOWED_CHAT_ID,
                "🤖 Авто-режим: кандидаты уже готовы, запускаю создание серверов",
            )
            start_provisioning_if_needed(networks)
            return {"ok": True, "auto_mode": True, "action": "start_provisioning", "finder": result}

        if result.get("started"):
            send(TELEGRAM_ALLOWED_CHAT_ID, f"🤖 Авто-режим: запускаю новый поиск\n{result.get('message', '')}")

        return {"ok": True, "auto_mode": True, "action": "start_finder", "finder": result}
    except Exception as e:
        error = str(e)
        update_finder_state(last_error=f"auto_mode: {error}")
        print(f"⚠️ Auto mode tick failed: {error}", flush=True)
        send(TELEGRAM_ALLOWED_CHAT_ID, f"⚠️ Авто-режим не смог продолжить цикл: {error}")
        return {"ok": False, "auto_mode": True, "action": "error", "error": error}


def enable_full_auto_mode(actor: str = "dashboard") -> dict:
    set_full_auto_mode(True)
    resume_all_testing()
    audit_log("full_auto_on", "", {}, actor=actor)
    tick = auto_mode_tick(reason=f"{actor}_enabled")
    return {"ok": True, "enabled": True, "tick": tick}


def disable_full_auto_mode(actor: str = "dashboard") -> dict:
    set_full_auto_mode(False)
    audit_log("full_auto_off", "", {}, actor=actor)
    return {"ok": True, "enabled": False}


# =========================
# MAIN LOOP
# =========================

def finder_loop():
    global running, last_good_ip_sync

    whitelist = []
    loaded_settings_version = -1
    attempt = 0

    while True:
        try:
            if not running:
                time.sleep(2)
                continue

            current_settings_version = get_settings_version()

            if not whitelist or loaded_settings_version != current_settings_version:
                try:
                    whitelist = load_whitelist()
                    loaded_settings_version = current_settings_version
                except Exception as e:
                    print(f"⚠️ Ошибка загрузки whitelist: {e}", flush=True)
                    running = False
                    send(TELEGRAM_ALLOWED_CHAT_ID, f"⚠️ Поиск остановлен: {e}")
                    time.sleep(10)
                    continue

            regions = get_selected_regions()
            if not regions:
                print("⚠️ Не выбран ни один регион", flush=True)
                running = False
                send(TELEGRAM_ALLOWED_CHAT_ID, "⚠️ Поиск остановлен: не выбран ни один регион")
                time.sleep(10)
                continue

            now = time.monotonic()
            slots_left = remaining_slots()
            if slots_left <= 0:
                print(f"🎯 Все слоты заполнены: {approved_count()}/{target_count()}", flush=True)
                running = False
                send(TELEGRAM_ALLOWED_CHAT_ID, f"🎯 Все слоты заполнены: {approved_count()}/{target_count()}")
                time.sleep(5)
                continue

            if now - last_good_ip_sync >= good_ip_sync_interval():
                current_count = sync_good_ips(whitelist, exclude_approved=True)
                last_good_ip_sync = now
            else:
                current_count = count_matching_good_ips(whitelist, exclude_approved=True)

            if current_count >= slots_left:
                print(
                    f"🎯 Кандидаты для свободных слотов найдены: {current_count}/{slots_left}; "
                    f"принято {approved_count()}/{target_count()}",
                    flush=True,
                )
                running = False
                if is_full_auto_mode_enabled():
                    send(
                        TELEGRAM_ALLOWED_CHAT_ID,
                        "🤖 Авто-режим: кандидаты для свободных слотов найдены\n"
                        f"✅ Принято ключей: {approved_count()}/{target_count()}\n"
                        f"📦 Новых кандидатов: {current_count}/{slots_left}\n\n"
                        "Finder остановлен. Запускаю создание серверов.",
                    )
                    start_provisioning_if_needed(whitelist)
                else:
                    send(
                        TELEGRAM_ALLOWED_CHAT_ID,
                        "🎯 Кандидаты для свободных слотов найдены\n"
                        f"✅ Принято ключей: {approved_count()}/{target_count()}\n"
                        f"📦 Новых кандидатов: {current_count}/{slots_left}\n\n"
                        "Finder остановлен. Серверы еще НЕ созданы.",
                        reply_markup=create_servers_keyboard(),
                    )
                time.sleep(5)
                continue

            attempt += 1
            region = random.choice(regions)
            update_finder_state(current_attempt=attempt, current_region=region, last_error="")

            print("=" * 70, flush=True)
            print(f"Попытка {attempt}", flush=True)
            print(f"🌍 Регион: {region}", flush=True)
            print(f"✅ Принято: {approved_count()}/{target_count()}", flush=True)
            print(f"📦 Новых кандидатов: {current_count}/{slots_left}", flush=True)
            print("=" * 70, flush=True)

            conn = None
            ip_id = None

            try:
                conn, ip_id, address = create_floating_ip(region)
                update_finder_state(last_ip=address)
                print(f"Получен IP: {address}", flush=True)

                if is_banned_ip(address):
                    print(f"🚫 IP в бан-листе, удаляем: {address}", flush=True)
                    delete_floating_ip(conn, ip_id)

                elif ip_allowed(address, whitelist):
                    save_good_ip(address, region, ip_id)

                    new_count = count_matching_good_ips(whitelist, exclude_approved=True)

                    print(f"✅ Подходит: {address} ({region})", flush=True)
                    print(f"📦 Новых кандидатов: {new_count}/{slots_left}", flush=True)
                    send(
                        TELEGRAM_ALLOWED_CHAT_ID,
                        f"✅ Подходит: {address} ({region})\n"
                        f"✅ Принято ключей: {approved_count()}/{target_count()}\n"
                        f"📦 Новых кандидатов: {new_count}/{slots_left}",
                    )

                    # IP оставляем, не удаляем

                else:
                    print(f"❌ Не подходит, удаляем: {address}", flush=True)
                    delete_floating_ip(conn, ip_id)

            except Exception as e:
                update_finder_state(last_error=str(e))
                print(f"⚠️ Ошибка создания IP в {region}:", flush=True)
                print(e, flush=True)

                if conn and ip_id:
                    delete_floating_ip(conn, ip_id)
            finally:
                close_connection(conn)
                if attempt % 50 == 0:
                    gc.collect()

            time.sleep(random.randint(5, 12))

        except Exception as e:
            print(f"🔥 Main loop error: {e}", flush=True)
            time.sleep(10)


# =========================
# START
# =========================

if __name__ == "__main__":
    print("🤖 Telegram бот запущен", flush=True)
    register_telegram_handlers(sys.modules[__name__])
    tester_api_server = start_tester_api_if_enabled(sys.modules[__name__])

    thread = threading.Thread(target=finder_loop, daemon=True)
    thread.start()

    while True:
        try:
            bot.infinity_polling(
                timeout=30,
                long_polling_timeout=30,
                skip_pending=True,
            )
        except Exception as e:
            print(f"⚠️ Telegram polling crashed: {e}", flush=True)
            time.sleep(10)
