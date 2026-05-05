import os
import sys
import time
import random
import ipaddress
import re
import threading
import base64
import secrets
import gc
import io
import subprocess
import json
import sqlite3
import html
import hmac
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from dataclasses import dataclass, field
from pathlib import Path

import telebot
import openstack
from telebot import types
from dotenv import load_dotenv

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
GOOD_IPS_FILE = BASE_DIR / "good_ips.txt"
BANNED_IPS_FILE = BASE_DIR / "banned_ips.txt"
APPROVED_KEYS_FILE = BASE_DIR / "approved_vless_keys.txt"
LOG_FILE = Path(os.getenv("LOG_FILE", str(BASE_DIR / "finder.log")).strip() or str(BASE_DIR / "finder.log"))


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
vless_queue_lock = threading.RLock()
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

bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)


SENSITIVE_ENV_NAMES = [
    "TELEGRAM_BOT_TOKEN",
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


@bot.message_handler(commands=["start"])
def cmd_start(message):
    global running, last_good_ip_sync

    if not allowed(message):
        bot.reply_to(message, "⛔ Access denied")
        return

    if running:
        bot.reply_to(message, "✅ Поиск уже запущен")
        return

    try:
        networks = load_whitelist()
    except Exception as e:
        bot.reply_to(message, f"⚠️ Не могу запустить поиск: {e}")
        return

    approved, existing_candidates, left_to_find = remaining_ips_to_find(networks)
    current_target = target_count()
    if approved >= current_target:
        bot.reply_to(message, f"✅ Уже есть {approved}/{current_target} рабочих ключей. Добор не нужен.")
        return

    if left_to_find <= 0:
        bot.reply_to(
            message,
            "✅ Кандидаты уже набраны. Поиск не нужен.\n"
            f"✅ Принято ключей: {approved}/{current_target}\n"
            f"📦 Найдено кандидатов: {existing_candidates}/{current_target - approved}\n\n"
            "Чтобы создать серверы и выдать ключи, нажми /create_servers.",
            reply_markup=create_servers_keyboard(),
        )
        return

    if not get_selected_regions():
        bot.reply_to(message, "⚠️ Не выбран ни один регион")
        return

    last_good_ip_sync = 0
    running = True
    update_finder_state(current_attempt=0, current_region="", last_ip="", last_error="", started_at=time.strftime("%Y-%m-%d %H:%M:%S"))
    bot.reply_to(
        message,
        "🚀 Поиск IP запущен\n"
        f"🎯 Целей: {len(networks)}\n"
        f"✅ Принято ключей: {approved}/{current_target}\n"
        f"📦 Уже найдено кандидатов: {existing_candidates}/{current_target - approved}\n"
        f"🔎 Осталось найти IP: {left_to_find}\n"
        f"🌍 Регионы: {format_regions()}",
    )


@bot.message_handler(commands=["stop"])
def cmd_stop(message):
    global running

    if not allowed(message):
        bot.reply_to(message, "⛔ Access denied")
        return

    running = False
    bot.reply_to(message, "⏸ Поиск IP остановлен")


@bot.message_handler(commands=["status"])
def cmd_status(message):
    if not allowed(message):
        bot.reply_to(message, "⛔ Access denied")
        return

    try:
        networks = load_whitelist()
        whitelist_status = f"{len(networks)}"
    except Exception as e:
        networks = None
        whitelist_status = f"ошибка: {e}"

    approved = approved_count()
    current_target = target_count()
    slots_left = max(current_target - approved, 0)
    count = sync_good_ips(networks, exclude_approved=True)
    left_to_find = max(slots_left - count, 0)
    state = "работает" if running else "остановлен"
    fs = get_finder_state()

    with provisioning_lock:
        provision_state = "идет" if provisioning_running else "ожидает"

    tester_stats = format_vless_queue_stats()
    control = get_tester_control_state()
    tester_pause_text = (
        f"tasks={'paused' if control['testing_paused'] else 'running'}, "
        f"servers={'paused' if control['provisioning_paused'] else 'running'}"
    )

    bot.reply_to(
        message,
        f"📊 Статус: {state}\n"
        f"🔁 Попытка: {fs.get('current_attempt') or 0}\n"
        f"🌍 Текущий регион: {fs.get('current_region') or '-'}\n"
        f"🌐 Последний IP: {fs.get('last_ip') or '-'}\n"
        f"⚠️ Последняя ошибка: {fs.get('last_error') or '-'}\n"
        f"🕒 Запущен: {fs.get('started_at') or '-'}\n"
        f"✅ Принято ключей: {approved}/{current_target}\n"
        f"📦 Найдено кандидатов: {count}/{slots_left}\n"
        f"🔎 Осталось найти IP: {left_to_find}\n"
        f"🎯 Целей в файле: {whitelist_status}\n"
        f"🌍 Регионы: {format_regions()}\n"
        f"🧪 Создание серверов: {provision_state}\n"
        f"📲 Авто-тестер: {tester_stats}\n"
        f"⏯ Test control: {tester_pause_text}\n"
        f"🚫 Бан-лист: {len(load_banned_ips())}"
    )


@bot.message_handler(commands=["test_status"])
def cmd_test_status(message):
    if not allowed(message):
        bot.reply_to(message, "⛔ Access denied")
        return

    stats = get_vless_queue_stats()
    recent = get_recent_vless_results(limit=8)
    api_state = "включен" if TESTER_API_ENABLED and TESTER_TOKEN else "выключен/нет токена"

    control = get_tester_control_state()
    lines = [
        "📲 Авто-тестер VLESS",
        f"API: {api_state}",
        f"Адрес: {TESTER_API_HOST}:{TESTER_API_PORT}",
        f"batch: {tester_batch_size()}",
        f"выдача задач телефону: {'paused ⏸' if control['testing_paused'] else 'running ▶️'}",
        f"создание серверов: {'paused ⏸' if control['provisioning_paused'] else 'running ▶️'}",
        "",
        "Очередь:",
        f"queued: {stats.get('queued', 0)}",
        f"testing: {stats.get('testing', 0)}",
        f"provisioning: {stats.get('provisioning', 0)}",
        f"approved: {stats.get('approved', 0)}",
        f"ip_not_suitable: {stats.get('ip_not_suitable_total', 0)}",
        f"vless_failed: {stats.get('vless_failed', 0)}",
        f"exit_ip_mismatch: {stats.get('exit_ip_mismatch', 0)}",
        f"phone_failed: {stats.get('phone_failed', 0)}",
        f"provision_failed: {stats.get('provision_failed', 0)}",
        f"manual_banned: {stats.get('manual_banned', 0)}",
        f"rejected: {stats.get('rejected', 0)}",
        f"error: {stats.get('error', 0)}",
    ]

    if recent:
        lines.append("")
        lines.append("Последние результаты:")
        for item in recent:
            status = item.get("status") or "-"
            ip = item.get("ip") or "-"
            worker = item.get("worker") or "-"
            latency = item.get("latency_ms")
            latency_text = f" {latency}ms" if latency is not None else ""
            lines.append(f"{status} | {ip}{latency_text} | {worker}")

    bot.reply_to(message, "\n".join(lines))


@bot.message_handler(commands=["test_stop", "pause_testing"])
def cmd_test_stop(message):
    if not allowed(message):
        bot.reply_to(message, "⛔ Access denied")
        return

    pause_all_testing()
    bot.reply_to(
        message,
        "⏸ Авто-тесты поставлены на паузу\n"
        "• телефонный worker останется online, но /next_tests будет возвращать пустой список\n"
        "• новые серверы создаваться не будут\n"
        "• уже выданная телефону задача может прислать результат",
    )


@bot.message_handler(commands=["test_start", "resume_testing"])
def cmd_test_start(message):
    if not allowed(message):
        bot.reply_to(message, "⛔ Access denied")
        return

    resume_all_testing()
    bot.reply_to(
        message,
        "▶️ Авто-тесты возобновлены\n"
        "• /next_tests снова может выдавать задачи\n"
        "• /create_servers снова может создавать серверы",
    )


@bot.message_handler(commands=["log"])
def cmd_log(message):
    if not allowed(message):
        bot.reply_to(message, "⛔ Access denied")
        return

    try:
        source = str(LOG_FILE)
        text = ""

        if LOG_FILE.exists():
            lines = LOG_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()[-200:]
            text = "\n".join(lines)
        else:
            # Fallback for older deployments where stdout/stderr only go to journald.
            source = "journalctl -u finder"
            result = subprocess.run(
                ["journalctl", "-u", "finder", "-n", "200", "--no-pager"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
                check=False,
            )
            text = result.stdout or ""

        if not text.strip():
            bot.reply_to(message, f"📜 Логи пустые или недоступны: {source}")
            return

        # Отправляем файлом, чтобы Telegram Markdown не ломался на спецсимволах из логов.
        data = io.BytesIO((text + "\n").encode("utf-8"))
        data.name = "finder_last_200_lines.log"
        bot.send_document(message.chat.id, data, caption=f"📜 Последние 200 строк логов ({source})")
    except Exception as e:
        bot.reply_to(message, f"⚠️ Не удалось отправить логи: {e}")


@bot.message_handler(commands=["create_servers"])
def cmd_create_servers(message):
    if not allowed(message):
        bot.reply_to(message, "⛔ Access denied")
        return

    if is_provisioning_paused():
        bot.reply_to(message, "⏸ Создание серверов на паузе. Используй /test_start для возобновления.")
        return

    try:
        networks = load_whitelist()
    except Exception as e:
        bot.reply_to(message, f"⚠️ Не могу загрузить whitelist: {e}")
        return

    candidates = count_matching_good_ips(networks, exclude_approved=True)
    slots_left = remaining_slots()
    if candidates <= 0:
        bot.reply_to(message, "⚠️ Нет найденных IP-кандидатов для создания серверов")
        return

    bot.reply_to(message, f"🚀 Запускаю создание серверов и выдачу ключей для {min(candidates, slots_left)} IP")
    start_provisioning_if_needed(networks)


@bot.message_handler(commands=["sync"])
def cmd_sync(message):
    if not allowed(message):
        bot.reply_to(message, "⛔ Access denied")
        return

    try:
        networks = load_whitelist()
    except Exception as e:
        bot.reply_to(message, f"⚠️ Не могу загрузить список целей: {e}")
        return

    count = sync_good_ips(networks, exclude_approved=True)
    bot.reply_to(
        message,
        "🔄 Синхронизация завершена.\n"
        f"✅ Принято ключей: {approved_count()}/{target_count()}\n"
        f"📦 Новых кандидатов: {count}/{remaining_slots()}",
    )


@bot.message_handler(commands=["upload"])
def cmd_upload(message):
    if not allowed(message):
        bot.reply_to(message, "⛔ Access denied")
        return

    set_waiting_for_whitelist_file(True)
    bot.reply_to(
        message,
        "📎 Жду файл со списком IP/CIDR.\n"
        "Отправь его документом в этот чат. Для отмены: /cancel",
    )


@bot.message_handler(commands=["cancel"])
def cmd_cancel(message):
    if not allowed(message):
        bot.reply_to(message, "⛔ Access denied")
        return

    if is_waiting_for_whitelist_file():
        set_waiting_for_whitelist_file(False)
        bot.reply_to(message, "✅ Ожидание файла отменено")
    else:
        bot.reply_to(message, "ℹ️ Сейчас я не жду файл")


@bot.message_handler(commands=["regions"])
def cmd_regions(message):
    if not allowed(message):
        bot.reply_to(message, "⛔ Access denied")
        return

    bot.reply_to(message, regions_text(), reply_markup=region_keyboard())


@bot.message_handler(commands=["help"])
def cmd_help(message):
    if not allowed(message):
        bot.reply_to(message, "⛔ Access denied")
        return

    bot.reply_to(message, help_text())


@bot.callback_query_handler(func=lambda call: call.data and call.data.startswith("region:"))
def callback_regions(call):
    if str(call.message.chat.id) != str(TELEGRAM_ALLOWED_CHAT_ID):
        bot.answer_callback_query(call.id, "Access denied", show_alert=True)
        return

    action = call.data.split(":", 2)

    try:
        if call.data == "region:all":
            set_selected_regions(REGIONS)
            bot.answer_callback_query(call.id, "Выбраны все регионы")
        elif call.data == "region:done":
            bot.answer_callback_query(call.id, "Готово")
        elif len(action) == 3 and action[1] == "toggle":
            region = action[2]
            current = get_selected_regions()
            if region in current and len(current) == 1:
                bot.answer_callback_query(call.id, "Нужен хотя бы один регион", show_alert=True)
                return
            if region in current:
                current.remove(region)
            else:
                current.append(region)
            set_selected_regions(current)
            bot.answer_callback_query(call.id, f"Регионы: {format_regions()}")
        else:
            bot.answer_callback_query(call.id, "Неизвестное действие", show_alert=True)
            return

        bot.edit_message_text(
            regions_text(),
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            reply_markup=region_keyboard(),
        )
    except Exception as e:
        bot.answer_callback_query(call.id, str(e), show_alert=True)


@bot.callback_query_handler(func=lambda call: call.data == "provision:start")
def callback_create_servers(call):
    if str(call.message.chat.id) != str(TELEGRAM_ALLOWED_CHAT_ID):
        bot.answer_callback_query(call.id, "Access denied", show_alert=True)
        return

    try:
        networks = load_whitelist()
        candidates = count_matching_good_ips(networks, exclude_approved=True)
        slots_left = remaining_slots()
        if candidates <= 0:
            bot.answer_callback_query(call.id, "Нет найденных IP", show_alert=True)
            return
        bot.answer_callback_query(call.id, "Запускаю создание серверов")
        send(TELEGRAM_ALLOWED_CHAT_ID, f"🚀 Запускаю создание серверов и выдачу ключей для {min(candidates, slots_left)} IP")
        start_provisioning_if_needed(networks)
    except Exception as e:
        bot.answer_callback_query(call.id, str(e), show_alert=True)


@bot.callback_query_handler(func=lambda call: call.data and call.data.startswith("vless:"))
def callback_vless_test(call):
    if str(call.message.chat.id) != str(TELEGRAM_ALLOWED_CHAT_ID):
        bot.answer_callback_query(call.id, "Access denied", show_alert=True)
        return

    parts = call.data.split(":", 2)
    if len(parts) != 3:
        bot.answer_callback_query(call.id, "Некорректная кнопка", show_alert=True)
        return

    _, result, token = parts
    if result not in {"ok", "bad"}:
        bot.answer_callback_query(call.id, "Некорректный результат", show_alert=True)
        return

    with provisioning_lock:
        pending = pending_vless_tests.get(token)

    if not pending:
        bot.answer_callback_query(call.id, "Эта проверка уже закрыта", show_alert=True)
        return

    pending.result = result
    pending.event.set()

    if result == "ok":
        bot.answer_callback_query(call.id, "Отмечено: работает")
    else:
        bot.answer_callback_query(call.id, "Отмечено: не работает")


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


@bot.message_handler(content_types=["document"])
def handle_whitelist_document(message):
    if not allowed(message):
        bot.reply_to(message, "⛔ Access denied")
        return

    if not is_waiting_for_whitelist_file():
        bot.reply_to(message, "ℹ️ Файл не обработан. Для загрузки списка IP/CIDR сначала отправь /upload")
        return

    document = message.document
    file_name = document.file_name or "file"

    if document.file_size and document.file_size > WHITELIST_MAX_BYTES:
        bot.reply_to(message, f"⚠️ Файл слишком большой. Максимум: {WHITELIST_MAX_BYTES} bytes")
        return

    try:
        file_info = bot.get_file(document.file_id)
        data = bot.download_file(file_info.file_path)
        count = save_whitelist_from_bytes(data)
    except Exception as e:
        bot.reply_to(message, f"⚠️ Не удалось загрузить список из файла {file_name}: {e}")
        return

    set_waiting_for_whitelist_file(False)
    suffix = "\nПоиск уже идет — новый список будет подхвачен автоматически." if running else ""
    bot.reply_to(
        message,
        f"✅ Список целей обновлен из файла {file_name}\n"
        f"🎯 Загружено IP/CIDR: {count}{suffix}",
    )


def ip_allowed(ip, networks) -> bool:
    ip_obj = ipaddress.ip_address(ip)
    return any(ip_obj in net for net in networks)


@dataclass
class GoodIpRecord:
    ip: str
    region: str
    ip_id: str = ""


@dataclass
class PendingVlessTest:
    token: str
    record: GoodIpRecord
    server_id: str
    vless_key: str
    event: threading.Event = field(default_factory=threading.Event)
    result: str = ""


def parse_good_ip_line(line: str) -> GoodIpRecord | None:
    parts = line.strip().split()
    if len(parts) < 2:
        return None

    ip, region = parts[0], parts[1]
    ip_id = ""

    for part in parts[2:]:
        if part.startswith("id="):
            ip_id = part.removeprefix("id=")

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"⚠️ Bad saved IP skipped: {line.strip()}", flush=True)
        return None

    return GoodIpRecord(ip=ip, region=region, ip_id=ip_id)


def load_good_ips() -> list[GoodIpRecord]:
    if not GOOD_IPS_FILE.exists():
        return []

    records = []
    seen = set()

    with open(GOOD_IPS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            record = parse_good_ip_line(line)
            if not record or record.ip in seen:
                continue

            records.append(record)
            seen.add(record.ip)

    return records


def write_good_ips(records: list[GoodIpRecord]):
    temp_file = GOOD_IPS_FILE.with_suffix(".tmp")

    with open(temp_file, "w", encoding="utf-8") as f:
        for record in records:
            suffix = f" id={record.ip_id}" if record.ip_id else ""
            f.write(f"{record.ip} {record.region}{suffix}\n")

    temp_file.replace(GOOD_IPS_FILE)


def load_banned_ips() -> set[str]:
    if not BANNED_IPS_FILE.exists():
        return set()

    banned = set()
    with open(BANNED_IPS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            ip = line.strip().split(maxsplit=1)[0] if line.strip() else ""
            if not ip:
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            banned.add(ip)

    return banned


def is_banned_ip(ip: str) -> bool:
    return ip in load_banned_ips()


def ban_ip(ip: str, reason: str = ""):
    banned = load_banned_ips()
    if ip in banned:
        return

    with open(BANNED_IPS_FILE, "a", encoding="utf-8") as f:
        suffix = f" {reason}" if reason else ""
        f.write(f"{ip}{suffix}\n")


def remove_good_ip(ip: str):
    records = [record for record in load_good_ips() if record.ip != ip]
    write_good_ips(records)


def save_approved_key(record: GoodIpRecord, vless_key: str):
    existing = set()
    if APPROVED_KEYS_FILE.exists():
        with open(APPROVED_KEYS_FILE, "r", encoding="utf-8") as f:
            existing = {line.strip().split()[0] for line in f if line.strip()}

    if record.ip in existing:
        return

    with open(APPROVED_KEYS_FILE, "a", encoding="utf-8") as f:
        f.write(f"{record.ip} {record.region} {vless_key}\n")


def load_approved_ips() -> set[str]:
    if not APPROVED_KEYS_FILE.exists():
        return set()

    with open(APPROVED_KEYS_FILE, "r", encoding="utf-8") as f:
        return {line.strip().split()[0] for line in f if line.strip()}


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
    if networks is None:
        return len([record for record in records if record.ip not in banned and record.ip not in approved])

    return len(
        [
            record
            for record in records
            if record.ip not in banned and record.ip not in approved and ip_allowed(record.ip, networks)
        ]
    )


def save_good_ip(ip, region, ip_id):
    if is_banned_ip(ip):
        return

    records = load_good_ips()
    existing = {record.ip for record in records}

    if ip in existing:
        return

    with open(GOOD_IPS_FILE, "a", encoding="utf-8") as f:
        f.write(f"{ip} {region} id={ip_id}\n")


# =========================
# OPENSTACK
# =========================

def get_connection(region):
    return openstack.connection.Connection(
        auth_url=OS_AUTH_URL,
        project_id=OS_PROJECT_ID or None,
        project_name=None if OS_PROJECT_ID else OS_PROJECT_NAME or None,
        username=OS_USERNAME,
        password=OS_PASSWORD,
        user_domain_name=OS_USER_DOMAIN_NAME,
        project_domain_name=OS_PROJECT_DOMAIN_NAME,
        region_name=region,
        interface=OS_INTERFACE,
        identity_api_version=OS_IDENTITY_API_VERSION,
        compute_api_version=OS_COMPUTE_API_VERSION,

        # prevent Selectel API hangs
        connect_retries=2,
        api_timeout=30,
    )


def close_connection(conn):
    if not conn:
        return
    try:
        close = getattr(conn, "close", None)
        if callable(close):
            close()
            return
        session = getattr(conn, "session", None) or getattr(conn, "_session", None)
        session_close = getattr(session, "close", None)
        if callable(session_close):
            session_close()
    except Exception:
        pass


def region_env(name: str, region: str) -> str:
    suffix = region.upper().replace("-", "_")
    return optional_env(f"{name}_{suffix}")


def get_floating_network(conn, region):
    network_id = region_env("FLOATING_NETWORK_ID", region) or FLOATING_NETWORK_ID
    network_name = region_env("FLOATING_NETWORK_NAME", region) or FLOATING_NETWORK_NAME

    if network_id:
        return conn.network.get_network(network_id)

    if network_name:
        network = conn.network.find_network(network_name, ignore_missing=True)
        if not network:
            raise RuntimeError(f"External network '{network_name}' not found in {region}")
        return network

    networks = list(conn.network.networks(is_router_external=True))

    if not networks:
        raise RuntimeError(f"No external networks found in {region}")

    if len(networks) > 1:
        found = ", ".join(
            f"{getattr(network, 'name', '<no-name>')} ({network.id})"
            for network in networks
        )
        raise RuntimeError(
            f"Multiple external networks found in {region}; set FLOATING_NETWORK_ID "
            f"or FLOATING_NETWORK_NAME in .env. Found: {found}"
        )

    return networks[0]


def create_floating_ip(region):
    conn = get_connection(region)

    try:
        network = get_floating_network(conn, region)
        ip = conn.network.create_ip(floating_network_id=network.id)

        address = ip.floating_ip_address
        ip_id = ip.id

        return conn, ip_id, address
    except Exception:
        close_connection(conn)
        raise


def delete_floating_ip(conn, ip_id):
    try:
        conn.network.delete_ip(ip_id, ignore_missing=True)
    except Exception as e:
        print(f"⚠️ Ошибка удаления IP {ip_id}: {e}", flush=True)


def saved_ip_active(record: GoodIpRecord) -> bool:
    conn = None
    try:
        conn = get_connection(record.region)

        if record.ip_id:
            ip = conn.network.find_ip(record.ip_id, ignore_missing=True)
            return bool(ip and getattr(ip, "floating_ip_address", "") == record.ip)

        for ip in conn.network.ips():
            if getattr(ip, "floating_ip_address", "") == record.ip:
                return True

        return False

    except Exception as e:
        print(f"⚠️ Не удалось проверить сохраненный IP {record.ip}: {e}", flush=True)
        return True
    finally:
        close_connection(conn)


def sync_good_ips(networks=None, exclude_approved=False) -> int:
    records = load_good_ips()
    if not records:
        return 0

    active_records = []
    matching_count = 0
    banned = load_banned_ips()
    approved = load_approved_ips() if exclude_approved else set()

    for record in records:
        if record.ip in banned:
            print(f"⚠️ Удаляю забаненную запись good_ips.txt: {record.ip}", flush=True)
            continue

        if saved_ip_active(record):
            active_records.append(record)
            if record.ip not in approved and (networks is None or ip_allowed(record.ip, networks)):
                matching_count += 1
        else:
            print(f"⚠️ Удаляю устаревшую запись good_ips.txt: {record.ip}", flush=True)

    if len(active_records) != len(records):
        write_good_ips(active_records)

    return matching_count


def matching_good_ip_records(networks=None, exclude_approved=False) -> list[GoodIpRecord]:
    banned = load_banned_ips()
    approved = load_approved_ips() if exclude_approved else set()
    records = []

    for record in load_good_ips():
        if record.ip in banned:
            continue
        if record.ip in approved:
            continue
        if networks is not None and not ip_allowed(record.ip, networks):
            continue
        records.append(record)

    return records



# =========================
# VLESS AUTO-TEST QUEUE / API
# =========================

IP_NOT_SUITABLE_STATUSES = {"ip_not_suitable", "phone_tcp_unreachable"}
PHONE_FAILURE_STATUSES = {"ip_not_suitable", "phone_tcp_unreachable", "vless_failed", "exit_ip_mismatch", "phone_failed"}
FINAL_VLESS_STATUSES = {"approved", "provision_failed", "manual_banned", "deleted", "rejected", "error", *PHONE_FAILURE_STATUSES}
ACTIVE_VLESS_STATUSES = {"queued", "testing", "provisioning"}
REVIEW_VLESS_STATUSES = {"provision_failed", "error", "rejected", *PHONE_FAILURE_STATUSES}
CONTROL_DEFAULTS = {
    "testing_paused": "0",
    "provisioning_paused": "0",
}


def now_ts() -> int:
    return int(time.time())


def get_vless_queue_conn():
    VLESS_QUEUE_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(VLESS_QUEUE_DB, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_vless_queue():
    with vless_queue_lock, get_vless_queue_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vless_tests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                region TEXT NOT NULL,
                ip_id TEXT,
                server_id TEXT,
                vless_key TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                attempts INTEGER NOT NULL DEFAULT 0,
                worker TEXT,
                exit_ip TEXT,
                direct_ip TEXT,
                latency_ms INTEGER,
                error TEXT,
                created_at INTEGER NOT NULL,
                reserved_at INTEGER,
                tested_at INTEGER
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vless_tests_status ON vless_tests(status, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vless_tests_worker ON vless_tests(worker, reserved_at)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vless_workers (
                worker TEXT PRIMARY KEY,
                updated_at INTEGER NOT NULL,
                control_ok INTEGER NOT NULL DEFAULT 0,
                api_ok INTEGER NOT NULL DEFAULT 0,
                current_task TEXT,
                last_error TEXT,
                network TEXT,
                battery TEXT,
                version TEXT,
                log_tail TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tester_control (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dashboard_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at INTEGER NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                details TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboard_audit_created ON dashboard_audit(created_at)")
        for key, value in CONTROL_DEFAULTS.items():
            conn.execute(
                """
                INSERT OR IGNORE INTO tester_control(key, value, updated_at)
                VALUES (?, ?, ?)
                """,
                (key, value, now_ts()),
            )


def get_tester_control_value(key: str, default: str = "0") -> str:
    init_vless_queue()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        row = conn.execute("SELECT value FROM tester_control WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else default


def set_tester_control_value(key: str, value: str):
    init_vless_queue()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        conn.execute(
            """
            INSERT INTO tester_control(key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            """,
            (key, value, now_ts()),
        )


def is_testing_paused() -> bool:
    return get_tester_control_value("testing_paused") == "1"


def is_provisioning_paused() -> bool:
    return get_tester_control_value("provisioning_paused") == "1"


def set_testing_paused(paused: bool):
    set_tester_control_value("testing_paused", "1" if paused else "0")


def set_provisioning_paused(paused: bool):
    set_tester_control_value("provisioning_paused", "1" if paused else "0")


def get_tester_control_state() -> dict:
    return {
        "testing_paused": is_testing_paused(),
        "provisioning_paused": is_provisioning_paused(),
    }


def audit_log(action: str, target: str = "", details: dict | None = None, actor: str = "dashboard"):
    try:
        init_vless_queue()
        details_text = json.dumps(details or {}, ensure_ascii=False, sort_keys=True)
        with vless_queue_lock, get_vless_queue_conn() as conn:
            conn.execute(
                """
                INSERT INTO dashboard_audit(created_at, actor, action, target, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    now_ts(),
                    redact_text(actor)[:80],
                    redact_text(action)[:120],
                    redact_text(target)[:200],
                    redact_text(details_text)[:4000],
                ),
            )
    except Exception as e:
        print(f"Audit log error: {e}", flush=True)


def get_audit_events(limit: int = 30) -> list[dict]:
    init_vless_queue()
    limit = max(1, min(int(limit or 30), 200))
    with vless_queue_lock, get_vless_queue_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, created_at, actor, action, target, details
            FROM dashboard_audit
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    events = []
    for row in rows:
        item = dict(row)
        item["details"] = redact_text(item.get("details") or "")
        events.append(item)
    return events


RUNTIME_SETTING_PREFIX = "setting:"
RUNTIME_SETTING_SPECS = [
    {
        "key": "TARGET_COUNT",
        "group": "Finder",
        "label": "Цель approved ключей",
        "kind": "int",
        "default": TARGET_COUNT,
        "min": 1,
        "max": 200,
    },
    {
        "key": "SELECTED_REGIONS",
        "group": "Finder",
        "label": "Регионы поиска",
        "kind": "regions",
        "default": REGIONS,
        "choices": REGIONS,
    },
    {
        "key": "GOOD_IP_SYNC_INTERVAL",
        "group": "Finder",
        "label": "Интервал sync good IP, сек",
        "kind": "int",
        "default": GOOD_IP_SYNC_INTERVAL,
        "min": 10,
        "max": 86400,
    },
    {
        "key": "PROVISION_PREEMPTIBLE_REGIONS",
        "group": "Provisioning",
        "label": "Preemptible регионы",
        "kind": "regions",
        "default": PROVISION_PREEMPTIBLE_REGIONS,
        "choices": DEFAULT_REGIONS,
    },
    {
        "key": "PROVISION_ALLOW_NON_PREEMPTIBLE",
        "group": "Provisioning",
        "label": "Разрешить обычные серверы",
        "kind": "bool",
        "default": PROVISION_ALLOW_NON_PREEMPTIBLE,
    },
    {
        "key": "PROVISION_SETUP_WAIT_SECONDS",
        "group": "Provisioning",
        "label": "Ожидание cloud-init/forwarding, сек",
        "kind": "int",
        "default": PROVISION_SETUP_WAIT_SECONDS,
        "min": 0,
        "max": 3600,
    },
    {
        "key": "PROVISION_SERVER_WAIT_SECONDS",
        "group": "Provisioning",
        "label": "Ожидание создания сервера, сек",
        "kind": "int",
        "default": PROVISION_SERVER_WAIT_SECONDS,
        "min": 30,
        "max": 3600,
    },
    {
        "key": "PROVISION_MAX_FLAVOR_ATTEMPTS",
        "group": "Provisioning",
        "label": "Максимум flavor попыток",
        "kind": "int",
        "default": PROVISION_MAX_FLAVOR_ATTEMPTS,
        "min": 1,
        "max": 100,
    },
    {
        "key": "PROVISION_TCP_CHECK_ENABLED",
        "group": "TCP check",
        "label": "Проверять TCP/443 с VPS",
        "kind": "bool",
        "default": PROVISION_TCP_CHECK_ENABLED,
    },
    {
        "key": "PROVISION_TCP_CHECK_TIMEOUT",
        "group": "TCP check",
        "label": "TCP timeout, сек",
        "kind": "int",
        "default": PROVISION_TCP_CHECK_TIMEOUT,
        "min": 1,
        "max": 120,
    },
    {
        "key": "PROVISION_TCP_CHECK_RETRIES",
        "group": "TCP check",
        "label": "TCP retries",
        "kind": "int",
        "default": PROVISION_TCP_CHECK_RETRIES,
        "min": 1,
        "max": 300,
    },
    {
        "key": "PROVISION_DELETE_SERVER_AFTER_RESULT",
        "group": "Cleanup",
        "label": "Удалять временный сервер после результата",
        "kind": "bool",
        "default": PROVISION_DELETE_SERVER_AFTER_RESULT,
    },
    {
        "key": "PROVISION_DELETE_FAILED_FLOATING_IP",
        "group": "Cleanup",
        "label": "Удалять Floating IP при failed provisioning",
        "kind": "bool",
        "default": PROVISION_DELETE_FAILED_FLOATING_IP,
    },
    {
        "key": "TESTER_BATCH_SIZE",
        "group": "Phone worker",
        "label": "Размер пачки задач",
        "kind": "int",
        "default": TESTER_BATCH_SIZE,
        "min": 1,
        "max": 100,
    },
    {
        "key": "TESTER_LEASE_SECONDS",
        "group": "Phone worker",
        "label": "Lease задачи, сек",
        "kind": "int",
        "default": TESTER_LEASE_SECONDS,
        "min": 30,
        "max": 86400,
    },
    {
        "key": "TESTER_MAX_ATTEMPTS",
        "group": "Phone worker",
        "label": "Максимум попыток worker",
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
    init_vless_queue()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        row = conn.execute(
            "SELECT value FROM tester_control WHERE key = ?",
            (RUNTIME_SETTING_PREFIX + key,),
        ).fetchone()
    return str(row["value"]) if row else None


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
    init_vless_queue()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        conn.execute("DELETE FROM tester_control WHERE key = ?", (RUNTIME_SETTING_PREFIX + key,))
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


def enqueue_vless_test(record: GoodIpRecord, server_id: str, vless_key: str, reset_attempts: bool = False) -> int | None:
    init_vless_queue()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        try:
            cur = conn.execute(
                """
                INSERT INTO vless_tests(ip, region, ip_id, server_id, vless_key, status, attempts, created_at)
                VALUES (?, ?, ?, ?, ?, 'queued', 0, ?)
                """,
                (record.ip, record.region, record.ip_id, server_id, vless_key, now_ts()),
            )
            return int(cur.lastrowid)
        except sqlite3.IntegrityError:
            row = conn.execute("SELECT id, status FROM vless_tests WHERE ip = ?", (record.ip,)).fetchone()
            if not row:
                return None
            if reset_attempts:
                conn.execute(
                    """
                    UPDATE vless_tests
                    SET region = ?, ip_id = ?, server_id = ?, vless_key = ?, status = 'queued',
                        attempts = 0, worker = NULL, exit_ip = NULL, direct_ip = NULL,
                        latency_ms = NULL, error = NULL, reserved_at = NULL, tested_at = NULL
                    WHERE id = ?
                    """,
                    (record.region, record.ip_id, server_id, vless_key, int(row["id"])),
                )
            return int(row["id"])


def get_vless_test_by_id(test_id: int) -> dict | None:
    init_vless_queue()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        row = conn.execute("SELECT * FROM vless_tests WHERE id = ?", (int(test_id),)).fetchone()
        return dict(row) if row else None


def get_vless_status_for_ip(ip: str) -> str:
    init_vless_queue()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        row = conn.execute("SELECT status FROM vless_tests WHERE ip = ?", (ip,)).fetchone()
        return str(row["status"]) if row else ""


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
    init_vless_queue()
    vless_key = vless_key or make_vless_key(record.ip)
    error = (error or "provision_failed")[:1000]
    now = now_ts()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        row = conn.execute("SELECT id FROM vless_tests WHERE ip = ?", (record.ip,)).fetchone()
        if row:
            test_id = int(row["id"])
            conn.execute(
                """
                UPDATE vless_tests
                SET region = ?, ip_id = ?, server_id = COALESCE(NULLIF(?, ''), server_id),
                    vless_key = ?, status = 'provision_failed', attempts = 0,
                    worker = NULL, exit_ip = NULL, direct_ip = NULL, latency_ms = NULL,
                    error = ?, reserved_at = NULL, tested_at = ?
                WHERE id = ?
                """,
                (record.region, record.ip_id, server_id, vless_key, error, now, test_id),
            )
            return test_id

        cur = conn.execute(
            """
            INSERT INTO vless_tests(ip, region, ip_id, server_id, vless_key, status, attempts, error, created_at, tested_at)
            VALUES (?, ?, ?, ?, ?, 'provision_failed', 0, ?, ?, ?)
            """,
            (record.ip, record.region, record.ip_id, server_id, vless_key, error, now, now),
        )
        return int(cur.lastrowid)


def reset_vless_test_to_queued(test_id: int) -> dict:
    init_vless_queue()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        row = conn.execute("SELECT * FROM vless_tests WHERE id = ?", (int(test_id),)).fetchone()
        if not row:
            raise RuntimeError("test not found")
        status = row["status"]
        if status not in REVIEW_VLESS_STATUSES:
            raise RuntimeError(f"retry is allowed only for failed/review statuses, current status={status}")
        if not row["server_id"]:
            raise RuntimeError("test has no server_id; use provisioning retry")
        conn.execute(
            """
            UPDATE vless_tests
            SET status = 'queued', attempts = 0, worker = NULL, exit_ip = NULL, direct_ip = NULL,
                latency_ms = NULL, error = NULL, reserved_at = NULL, tested_at = NULL
            WHERE id = ?
            """,
            (int(test_id),),
        )
        return {"id": int(test_id), "status": "queued"}


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
        result = {"id": int(task_id or test_id), "status": "provision_failed", "error": error}
        audit_log("retry_blocked_region", str(test_id), result, actor=actor)
        return result

    with vless_queue_lock, get_vless_queue_conn() as conn:
        conn.execute(
            """
            UPDATE vless_tests
            SET status = 'provisioning', attempts = 0, worker = NULL, exit_ip = NULL, direct_ip = NULL,
                latency_ms = NULL, error = 'manual retry: provisioning started', reserved_at = NULL, tested_at = NULL
            WHERE id = ?
            """,
            (int(test_id),),
        )

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
            delete_floating_ip_address(conn, record.ip, record.ip_id)
        except Exception as e:
            cleanup_errors.append(f"floating ip delete: {e}")
    finally:
        close_connection(conn)

    ban_ip(record.ip, f"manual_dashboard_delete region={record.region}")
    remove_good_ip(record.ip)
    error_text = "; ".join(cleanup_errors) if cleanup_errors else "manual dashboard delete"
    with vless_queue_lock, get_vless_queue_conn() as db:
        db.execute(
            """
            UPDATE vless_tests
            SET status = 'manual_banned', worker = NULL, error = ?, reserved_at = NULL, tested_at = ?
            WHERE id = ?
            """,
            (error_text[:1000], now_ts(), int(test_id)),
        )

    result = {"id": int(test_id), "status": "manual_banned", "cleanup_errors": cleanup_errors}
    audit_log("delete_ip", str(test_id), {"ip": record.ip, "region": record.region, "status": status, "cleanup_errors": cleanup_errors}, actor=actor)
    return result


def select_test_ids(statuses: list[str] | None = None, region: str = "", older_than: int | None = None, limit: int = 100) -> list[int]:
    init_vless_queue()
    clauses = []
    params = []
    if statuses:
        placeholders = ",".join("?" for _ in statuses)
        clauses.append(f"status IN ({placeholders})")
        params.extend(statuses)
    if region:
        clauses.append("region = ?")
        params.append(region)
    if older_than is not None:
        clauses.append("COALESCE(tested_at, reserved_at, created_at) < ?")
        params.append(int(older_than))
    where = " AND ".join(clauses) if clauses else "1=1"
    limit = max(1, min(int(limit or 100), 300))
    with vless_queue_lock, get_vless_queue_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT id
            FROM vless_tests
            WHERE {where}
            ORDER BY COALESCE(tested_at, reserved_at, created_at) ASC
            LIMIT ?
            """,
            [*params, limit],
        ).fetchall()
    return [int(row["id"]) for row in rows]


def mark_region_tests_provision_failed(region: str, actor: str = "dashboard") -> dict:
    if region not in DEFAULT_REGIONS and region not in REGIONS:
        raise RuntimeError(f"unknown region: {region}")
    error = region_provision_block_reason(region)
    now = now_ts()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        cur = conn.execute(
            """
            UPDATE vless_tests
            SET status = 'provision_failed', attempts = 0, worker = NULL,
                error = ?, reserved_at = NULL, tested_at = ?
            WHERE region = ?
              AND status NOT IN ('approved', 'manual_banned', 'deleted')
            """,
            (error, now, region),
        )
        changed = int(cur.rowcount or 0)
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


def get_vless_queue_stats() -> dict:
    init_vless_queue()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) AS cnt FROM vless_tests GROUP BY status"
        ).fetchall()
        stats = {row["status"]: int(row["cnt"]) for row in rows}
    for status in ["queued", "testing", "provisioning", "approved", "ip_not_suitable", "phone_tcp_unreachable", "vless_failed", "exit_ip_mismatch", "phone_failed", "provision_failed", "manual_banned", "rejected", "error"]:
        stats.setdefault(status, 0)
    stats["ip_not_suitable_total"] = stats.get("ip_not_suitable", 0) + stats.get("phone_tcp_unreachable", 0)
    return stats


def format_vless_queue_stats() -> str:
    stats = get_vless_queue_stats()
    return (
        f"queued={stats.get('queued', 0)}, "
        f"testing={stats.get('testing', 0)}, "
        f"approved={stats.get('approved', 0)}, "
        f"ip_not_suitable={stats.get('ip_not_suitable_total', 0)}, "
        f"vless_failed={stats.get('vless_failed', 0)}, "
        f"exit_mismatch={stats.get('exit_ip_mismatch', 0)}, "
        f"provision_failed={stats.get('provision_failed', 0)}"
    )


def load_approved_region_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    if not APPROVED_KEYS_FILE.exists():
        return counts
    with open(APPROVED_KEYS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 2:
                counts[parts[1]] = counts.get(parts[1], 0) + 1
    return counts


def region_diagnostics() -> list[dict]:
    good_counts: dict[str, int] = {}
    for record in load_good_ips():
        good_counts[record.region] = good_counts.get(record.region, 0) + 1
    approved_region_counts = load_approved_region_counts()

    by_region: dict[str, dict] = {}
    init_vless_queue()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        rows = conn.execute(
            """
            SELECT region, status, COUNT(*) AS cnt
            FROM vless_tests
            GROUP BY region, status
            """
        ).fetchall()
        last_rows = conn.execute(
            """
            SELECT region, status, error, COALESCE(tested_at, reserved_at, created_at) AS ts
            FROM vless_tests
            WHERE error IS NOT NULL AND error != ''
            ORDER BY COALESCE(tested_at, reserved_at, created_at) DESC
            """
        ).fetchall()

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


def dashboard_metrics() -> dict:
    day_ago = now_ts() - 86400
    init_vless_queue()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        rows = conn.execute(
            """
            SELECT status, COUNT(*) AS cnt
            FROM vless_tests
            WHERE COALESCE(tested_at, reserved_at, created_at) >= ?
            GROUP BY status
            """,
            (day_ago,),
        ).fetchall()
        latency = conn.execute(
            """
            SELECT AVG(latency_ms) AS avg_latency
            FROM vless_tests
            WHERE status = 'approved' AND latency_ms IS NOT NULL
            """
        ).fetchone()
    last24 = {row["status"]: int(row["cnt"]) for row in rows}
    last24["ip_not_suitable_total"] = last24.get("ip_not_suitable", 0) + last24.get("phone_tcp_unreachable", 0)
    return {
        "last24": last24,
        "avg_approved_latency_ms": int(latency["avg_latency"]) if latency and latency["avg_latency"] is not None else None,
    }


def active_server_ids() -> set[str]:
    init_vless_queue()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        rows = conn.execute(
            """
            SELECT server_id
            FROM vless_tests
            WHERE server_id IS NOT NULL AND server_id != ''
              AND status IN ('queued', 'testing', 'provisioning')
            """
        ).fetchall()
    return {str(row["server_id"]) for row in rows if row["server_id"]}


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


def get_recent_vless_results(limit: int = 10) -> list[dict]:
    init_vless_queue()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, ip, region, status, worker, exit_ip, latency_ms, error, tested_at
            FROM vless_tests
            WHERE tested_at IS NOT NULL
            ORDER BY tested_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    results = []
    for row in rows:
        item = dict(row)
        item["error"] = redact_text(item.get("error") or "")
        item["display_status"] = "ip_not_suitable" if item.get("status") in IP_NOT_SUITABLE_STATUSES else item.get("status")
        results.append(item)
    return results


def reserve_vless_tests(worker: str, limit: int) -> list[dict]:
    init_vless_queue()
    worker = (worker or "unknown-worker")[:80]
    batch_size = tester_batch_size()
    limit = max(1, min(int(limit or batch_size), batch_size))
    max_attempts = tester_max_attempts()
    now = now_ts()
    stale_before = now - tester_lease_seconds()

    with vless_queue_lock, get_vless_queue_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            """
            SELECT id
            FROM vless_tests
            WHERE attempts < ?
              AND (
                    status = 'queued'
                    OR (status = 'testing' AND reserved_at IS NOT NULL AND reserved_at < ?)
                  )
            ORDER BY created_at ASC
            LIMIT ?
            """,
            (max_attempts, stale_before, limit),
        ).fetchall()
        ids = [int(row["id"]) for row in rows]
        if not ids:
            conn.commit()
            return []

        placeholders = ",".join("?" for _ in ids)
        conn.execute(
            f"""
            UPDATE vless_tests
            SET status = 'testing',
                attempts = attempts + 1,
                worker = ?,
                reserved_at = ?,
                error = NULL
            WHERE id IN ({placeholders})
            """,
            [worker, now, *ids],
        )
        tasks = conn.execute(
            f"""
            SELECT id, ip, region, server_id, vless_key, attempts
            FROM vless_tests
            WHERE id IN ({placeholders})
            ORDER BY created_at ASC
            """,
            ids,
        ).fetchall()
        conn.commit()

    return [
        {
            "id": int(row["id"]),
            "ip": row["ip"],
            "region": row["region"],
            "server_id": row["server_id"],
            "vless_url": row["vless_key"],
            "attempts": int(row["attempts"]),
        }
        for row in tasks
    ]


def complete_vless_test_result(result: dict, worker: str = "") -> dict:
    init_vless_queue()
    test_id = int(result.get("id") or 0)
    ok = bool(result.get("ok"))
    exit_ip = (result.get("exit_ip") or "")[:80]
    direct_ip = (result.get("direct_ip") or "")[:80]
    error = (result.get("error") or "")[:1000]
    latency_ms = result.get("latency_ms")
    try:
        latency_ms = int(latency_ms) if latency_ms is not None else None
    except (TypeError, ValueError):
        latency_ms = None

    with vless_queue_lock, get_vless_queue_conn() as conn:
        row = conn.execute("SELECT * FROM vless_tests WHERE id = ?", (test_id,)).fetchone()
        if not row:
            return {"id": test_id, "saved": False, "status": "unknown_id"}

        old_status = row["status"]
        if old_status in FINAL_VLESS_STATUSES:
            return {"id": test_id, "saved": True, "status": old_status, "already_final": True}

        record = GoodIpRecord(ip=row["ip"], region=row["region"], ip_id=row["ip_id"] or "")
        server_id = row["server_id"] or ""
        vless_key = row["vless_key"]
        now = now_ts()

        if ok:
            conn.execute(
                """
                UPDATE vless_tests
                SET status = 'approved', worker = COALESCE(?, worker), exit_ip = ?, direct_ip = ?,
                    latency_ms = ?, error = NULL, reserved_at = NULL, tested_at = ?
                WHERE id = ?
                """,
                (worker or None, exit_ip, direct_ip, latency_ms, now, test_id),
            )
            final_status = "approved"
        else:
            final_status = classify_phone_failure(error)
            conn.execute(
                """
                UPDATE vless_tests
                SET status = ?, worker = COALESCE(?, worker), exit_ip = ?, direct_ip = ?,
                    latency_ms = ?, error = ?, reserved_at = NULL, tested_at = ?
                WHERE id = ?
                """,
                (final_status, worker or None, exit_ip, direct_ip, latency_ms, error or "phone test failed", now, test_id),
            )

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


def save_worker_heartbeat(payload: dict, worker: str = "") -> dict:
    init_vless_queue()
    worker = (worker or payload.get("worker") or "unknown-worker")[:80]
    now = now_ts()

    def cut(name: str, limit: int = 1000) -> str:
        return redact_text(payload.get(name) or "")[:limit]

    control_ok = 1 if payload.get("control_ok") else 0
    api_ok = 1 if payload.get("api_ok", True) else 0
    current_task = cut("current_task", 200)
    last_error = cut("last_error", 1000)
    network = cut("network", 120)
    battery = cut("battery", 80)
    version = cut("version", 80)
    log_tail = cut("log_tail", 12000)

    with vless_queue_lock, get_vless_queue_conn() as conn:
        conn.execute(
            """
            INSERT INTO vless_workers(worker, updated_at, control_ok, api_ok, current_task, last_error, network, battery, version, log_tail)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(worker) DO UPDATE SET
                updated_at = excluded.updated_at,
                control_ok = excluded.control_ok,
                api_ok = excluded.api_ok,
                current_task = excluded.current_task,
                last_error = excluded.last_error,
                network = excluded.network,
                battery = excluded.battery,
                version = excluded.version,
                log_tail = excluded.log_tail
            """,
            (worker, now, control_ok, api_ok, current_task, last_error, network, battery, version, log_tail),
        )
    return {"worker": worker, "saved": True, "updated_at": now}


def get_worker_statuses() -> list[dict]:
    init_vless_queue()
    now = now_ts()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        rows = conn.execute(
            """
            SELECT worker, updated_at, control_ok, api_ok, current_task, last_error, network, battery, version, log_tail
            FROM vless_workers
            ORDER BY updated_at DESC
            """
        ).fetchall()
    workers = []
    for row in rows:
        item = dict(row)
        item["control_ok"] = bool(item.get("control_ok"))
        item["api_ok"] = bool(item.get("api_ok"))
        item["last_error"] = redact_text(item.get("last_error") or "")
        item["current_task"] = redact_text(item.get("current_task") or "")
        item["log_tail"] = redact_text(item.get("log_tail") or "")
        item["age_seconds"] = max(0, now - int(item.get("updated_at") or 0))
        item["online"] = item["age_seconds"] <= 90
        workers.append(item)
    return workers


def get_recent_vless_tests(limit: int = 50) -> list[dict]:
    init_vless_queue()
    limit = max(1, min(int(limit or 50), 200))
    with vless_queue_lock, get_vless_queue_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, ip, region, status, attempts, worker, exit_ip, direct_ip, latency_ms, error, created_at, reserved_at, tested_at
            FROM vless_tests
            ORDER BY COALESCE(tested_at, reserved_at, created_at) DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        tests = []
        for row in rows:
            item = dict(row)
            item["error"] = redact_text(item.get("error") or "")
            item["display_status"] = "ip_not_suitable" if item.get("status") in IP_NOT_SUITABLE_STATUSES else item.get("status")
            tests.append(item)
        return tests


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
        "tests": get_recent_vless_tests(limit=50),
        "audit": get_audit_events(limit=20),
        "logs": {
            "finder": tail_file_text(LOG_FILE, DASHBOARD_LOG_LINES),
        },
    }


def dashboard_html() -> str:
    return """<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Selectel Finder Dashboard</title>
  <style>
    :root { color-scheme: dark; --bg:#0b1020; --card:#121a2d; --muted:#91a0bd; --line:#26324f; --good:#34d399; --bad:#fb7185; --warn:#fbbf24; --text:#e5edff; }
    * { box-sizing: border-box; }
    body { margin:0; font-family: system-ui, -apple-system, Segoe UI, sans-serif; background:var(--bg); color:var(--text); }
    header { position:sticky; top:0; z-index:10; background:rgba(11,16,32,.92); border-bottom:1px solid var(--line); padding:14px 18px; backdrop-filter: blur(8px); }
    h1 { margin:0; font-size:20px; }
    main { padding:18px; max-width:1500px; margin:0 auto; }
    .grid { display:grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap:14px; }
    .card { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:14px; box-shadow: 0 10px 30px rgba(0,0,0,.18); }
    .card h2 { margin:0 0 10px; font-size:15px; color:#c8d6f7; }
    .num { font-size:28px; font-weight:800; }
    .muted { color:var(--muted); font-size:13px; }
    .ok { color:var(--good); } .bad { color:var(--bad); } .warn { color:var(--warn); }
    table { width:100%; border-collapse: collapse; font-size:13px; }
    th,td { text-align:left; border-bottom:1px solid var(--line); padding:8px 7px; vertical-align:top; }
    th { color:#b8c6e6; font-weight:700; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    pre { white-space:pre-wrap; word-break:break-word; max-height:380px; overflow:auto; background:#080d19; border:1px solid var(--line); border-radius:12px; padding:12px; font-size:12px; }
    .span4 { grid-column: span 4; }
    .span2 { grid-column: span 2; }
    .badge { display:inline-block; border-radius:999px; padding:2px 8px; background:#1e2a46; border:1px solid var(--line); font-size:12px; }
    .row { display:flex; align-items:center; justify-content:space-between; gap:12px; }
    .toolbar { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
    input, select { background:#080d19; border:1px solid var(--line); color:var(--text); border-radius:10px; padding:8px 10px; }
    .scroll { overflow:auto; }
    button, a.button { background:#2563eb; color:white; border:0; border-radius:10px; padding:8px 10px; font-weight:700; cursor:pointer; margin:2px; text-decoration:none; display:inline-block; }
    button:hover, a.button:hover { background:#1d4ed8; }
    button.danger { background:#b91c1c; }
    button.danger:hover { background:#991b1b; }
    button.secondary, a.button.secondary { background:#475569; }
    button.secondary:hover, a.button.secondary:hover { background:#334155; }
    @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } .span4,.span2 { grid-column: span 1; } table { font-size:12px; } }
  </style>
</head>
<body>
<header><div class="row"><h1>🚀 Selectel Finder Dashboard</h1><button onclick="load()">Обновить</button></div><div class="muted" id="updated">загрузка...</div></header>
<main>
  <p><a class="button secondary" href="/dashboard/settings">Настройки</a></p>
  <div class="grid">
    <div class="card"><h2>Finder</h2><div class="num" id="finderState">-</div><div class="muted" id="finderMeta"></div></div>
    <div class="card"><h2>Approved</h2><div class="num ok" id="approved">0</div><div class="muted" id="target"></div></div>
    <div class="card"><h2>Queue</h2><div class="num" id="queueTotal">0</div><div class="muted" id="queueMeta"></div></div>
    <div class="card"><h2>Workers</h2><div class="num" id="workersTotal">0</div><div class="muted" id="workersMeta"></div></div>
    <div class="card span4"><h2>Bulk / обслуживание</h2><div class="toolbar">
      <button class="danger" onclick="bulkAction('delete_ip_not_suitable')">Удалить все IP не подходят</button>
      <button class="secondary" onclick="bulkAction('retry_vless_failed')">Retry все vless_failed</button>
      <select id="bulkRegion"></select><button class="secondary" onclick="bulkAction('mark_region_provision_failed')">Регион в provision_failed</button>
      <input id="oldDays" type="number" min="1" max="365" value="7" style="width:88px"><button class="danger" onclick="bulkAction('delete_old_provision_failed')">Удалить старые provision_failed</button>
      <button class="secondary" onclick="bulkAction('reconcile_dry_run')">Reconcile dry-run</button>
      <button class="danger" onclick="bulkAction('cleanup_stale_temp_servers')">Cleanup stale temp servers</button>
    </div><div class="muted" id="bulkResult"></div></div>
    <div class="card span2"><h2>Метрики</h2><div id="metrics"></div></div>
    <div class="card span2"><h2>Audit</h2><div id="audit"></div></div>
    <div class="card span4"><h2>Регионы</h2><div class="scroll"><table id="regions"><thead><tr><th>Регион</th><th>Поиск</th><th>Preemptible</th><th>Provision</th><th>Good</th><th>Approved</th><th>IP не подходит</th><th>vless_failed</th><th>provision_failed</th><th>Success</th><th>Последняя ошибка</th></tr></thead><tbody></tbody></table></div></div>
    <div class="card span2"><h2>Телефон / workers</h2><div id="workers"></div></div>
    <div class="card span2"><h2>Состояние</h2><div id="state"></div></div>
    <div class="card span4"><h2>Последние тесты</h2><div style="overflow:auto"><table id="tests"><thead><tr><th>ID</th><th>IP</th><th>Регион</th><th>Статус</th><th>Поп.</th><th>Worker</th><th>Exit IP</th><th>ms</th><th>Ошибка</th><th>Действия</th></tr></thead><tbody></tbody></table></div></div>
    <div class="card span2"><h2>Лог телефона</h2><pre id="phoneLog"></pre></div>
    <div class="card span2"><h2>Лог VPS</h2><pre id="finderLog"></pre></div>
  </div>
</main>
<script>
function esc(s){return String(s ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));}
function age(s){ if(s == null) return '-'; if(s < 60) return s+' сек'; if(s < 3600) return Math.round(s/60)+' мин'; return Math.round(s/3600)+' ч'; }
function isIpNotSuitable(status){ return ['ip_not_suitable','phone_tcp_unreachable'].includes(status); }
function canAct(status){ return ['ip_not_suitable','phone_tcp_unreachable','vless_failed','exit_ip_mismatch','phone_failed','provision_failed','rejected','error'].includes(status); }
function actionButtons(t){
  if(!canAct(t.status)) return '';
  const deleteLabel = isIpNotSuitable(t.status) ? 'Отклонить IP' : 'Удалить IP';
  return `<button class="secondary" onclick="dashAction('retry', ${t.id})">Повторить</button><button class="danger" onclick="dashAction('delete', ${t.id})">${deleteLabel}</button>`;
}
function diagnosticText(t){
  const raw = esc(t.error || '');
  if(isIpNotSuitable(t.status)){
    return `<b class="warn">IP не подходит</b>${raw ? '<br><span class="muted">'+raw+'</span>' : ''}`;
  }
  return raw;
}
async function dashAction(action, id){
  const label = action === 'delete' ? 'удалить IP, сервер/floating IP и добавить в бан' : 'повторить проверку';
  if(!confirm(`ID ${id}: ${label}?`)) return;
  const r = await fetch('/dashboard/api/action', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action, id})});
  const data = await r.json().catch(()=>({ok:false,error:'bad json'}));
  if(!r.ok || !data.ok){ alert('Ошибка: ' + (data.error || r.status)); return; }
  await load();
}
async function bulkAction(action){
  const payload = {action, limit:100};
  if(action === 'mark_region_provision_failed') payload.region = document.getElementById('bulkRegion').value;
  if(action === 'delete_old_provision_failed') payload.days = Number(document.getElementById('oldDays').value || 7);
  const destructive = ['delete_ip_not_suitable','delete_old_provision_failed','cleanup_stale_temp_servers'].includes(action);
  if(destructive && !confirm('Запустить bulk action: ' + action + '?')) return;
  const r = await fetch('/dashboard/api/bulk_action', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
  const data = await r.json().catch(()=>({ok:false,error:'bad json'}));
  if(!r.ok || !data.ok){ alert('Ошибка: ' + (data.error || r.status)); return; }
  document.getElementById('bulkResult').textContent = JSON.stringify(data.result || {count:data.count, errors:data.errors || []}).slice(0, 900);
  await load();
}
async function load(){
  const r = await fetch('/dashboard/api/status', {cache:'no-store'});
  if(!r.ok){ document.getElementById('updated').textContent='ошибка загрузки: '+r.status; return; }
  const d = await r.json();
  document.getElementById('updated').textContent = 'обновлено: ' + new Date(d.generated_at*1000).toLocaleString();
  document.getElementById('finderState').innerHTML = d.finder.running ? '<span class="ok">работает</span>' : '<span class="warn">стоп</span>';
  document.getElementById('finderMeta').textContent = 'регион: ' + (d.finder.current_region || '-') + ', попытка: ' + d.finder.current_attempt;
  document.getElementById('approved').textContent = d.counts.approved;
  document.getElementById('target').textContent = 'цель: ' + d.counts.target + ', кандидаты: ' + d.counts.candidates + ', ban: ' + d.counts.banned;
  const q = d.queue || {}; const total = (q.queued||0)+(q.testing||0)+(q.provisioning||0);
  document.getElementById('queueTotal').textContent = total;
  document.getElementById('queueMeta').textContent = `queued=${q.queued||0}, testing=${q.testing||0}, provisioning=${q.provisioning||0}, approved=${q.approved||0}, ip_not_suitable=${q.ip_not_suitable_total||0}, vless_failed=${q.vless_failed||0}, exit_mismatch=${q.exit_ip_mismatch||0}, phone_failed=${q.phone_failed||0}, provision_failed=${q.provision_failed||0}, banned=${q.manual_banned||0}`;
  document.getElementById('workersTotal').textContent = (d.workers||[]).length;
  document.getElementById('workersMeta').textContent = (d.workers||[]).filter(w=>w.online).length + ' online';
  const c = d.control || {};
  document.getElementById('state').innerHTML = `<p>Testing: <b class="${c.testing_paused?'warn':'ok'}">${c.testing_paused?'paused':'running'}</b></p><p>Provisioning: <b class="${c.provisioning_paused?'warn':'ok'}">${esc(d.provisioning.state)}${c.provisioning_paused?' / paused':''}</b></p><p>Последний IP: <code>${esc(d.finder.last_ip || '-')}</code></p><p>Последняя ошибка: <span class="bad">${esc(d.finder.last_error || '-')}</span></p><p>Регионы: ${esc((d.finder.selected_regions||[]).join(', '))}</p>`;
  const workers = d.workers || [];
  const regionSelect = document.getElementById('bulkRegion');
  const currentRegion = regionSelect.value;
  regionSelect.innerHTML = (d.regions||[]).map(r => `<option value="${esc(r.region)}">${esc(r.region)}</option>`).join('');
  if(currentRegion) regionSelect.value = currentRegion;
  const m = d.metrics || {}; const last24 = m.last24 || {};
  document.getElementById('metrics').innerHTML = `<p>24h approved: <b class="ok">${last24.approved||0}</b></p><p>24h IP не подходит: <b class="warn">${last24.ip_not_suitable_total||0}</b></p><p>24h vless_failed: <b class="bad">${last24.vless_failed||0}</b></p><p>avg approved latency: ${m.avg_approved_latency_ms || '-'} ms</p>`;
  document.getElementById('audit').innerHTML = (d.audit||[]).slice(0,8).map(a => `<div style="margin-bottom:8px"><span class="badge">${esc(a.action)}</span> <span class="muted">${new Date(a.created_at*1000).toLocaleString()}</span><br>${esc(a.target||'')}<br><span class="muted">${esc(a.details||'')}</span></div>`).join('') || '<span class="muted">пока нет изменений</span>';
  document.querySelector('#regions tbody').innerHTML = (d.regions||[]).map(r => {
    const s = r.statuses || {};
    return `<tr><td><code>${esc(r.region)}</code></td><td>${r.selected?'yes':'-'}</td><td>${r.preemptible?'yes':'-'}</td><td><span class="${r.can_provision?'ok':'bad'}">${r.can_provision?'yes':'no'}</span></td><td>${r.good_ips||0}</td><td>${r.approved_keys||0}</td><td>${s.ip_not_suitable_total||0}</td><td>${s.vless_failed||0}</td><td>${s.provision_failed||0}</td><td>${r.success_rate == null ? '-' : r.success_rate+'%'}</td><td class="bad">${esc(r.last_error||'')}</td></tr>`;
  }).join('');
  document.getElementById('workers').innerHTML = workers.length ? workers.map(w => `<div style="margin-bottom:10px"><span class="badge ${w.online?'ok':'bad'}">${w.online?'online':'offline'}</span> <b>${esc(w.worker)}</b><br><span class="muted">last seen: ${age(w.age_seconds)}, control=${w.control_ok?'OK':'NO'}, api=${w.api_ok?'OK':'NO'}, task=${esc(w.current_task||'-')}</span><br><span class="bad">${esc(w.last_error||'')}</span></div>`).join('') : '<span class="muted">нет heartbeat от телефона</span>';
  const lastWorker = workers[0];
  document.getElementById('phoneLog').textContent = lastWorker && lastWorker.log_tail ? lastWorker.log_tail : 'Пока нет логов телефона. Обнови termux_vless_tester.py до dashboard-версии.';
  document.getElementById('finderLog').textContent = d.logs.finder || 'лог пуст';
  const tbody = document.querySelector('#tests tbody');
  tbody.innerHTML = (d.tests||[]).map(t => `<tr><td>${t.id}</td><td><code>${esc(t.ip)}</code></td><td>${esc(t.region)}</td><td><span class="badge">${esc(t.display_status || t.status)}</span></td><td>${t.attempts||0}</td><td>${esc(t.worker||'-')}</td><td>${esc(t.exit_ip||'-')}</td><td>${esc(t.latency_ms||'-')}</td><td class="bad">${diagnosticText(t)}</td><td>${actionButtons(t)}</td></tr>`).join('');
}
load(); setInterval(load, 10000);
</script>
</body>
</html>"""


def dashboard_settings_html() -> str:
    return """<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Selectel Finder Settings</title>
  <style>
    :root { color-scheme: dark; --bg:#0b1020; --card:#121a2d; --muted:#91a0bd; --line:#26324f; --good:#34d399; --bad:#fb7185; --warn:#fbbf24; --text:#e5edff; }
    * { box-sizing: border-box; }
    body { margin:0; font-family: system-ui, -apple-system, Segoe UI, sans-serif; background:var(--bg); color:var(--text); }
    header { position:sticky; top:0; z-index:10; background:rgba(11,16,32,.92); border-bottom:1px solid var(--line); padding:14px 18px; backdrop-filter: blur(8px); }
    h1 { margin:0; font-size:20px; }
    main { padding:18px; max-width:1100px; margin:0 auto; }
    .row { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; }
    .group { margin:0 0 16px; background:var(--card); border:1px solid var(--line); border-radius:16px; padding:14px; }
    .group h2 { margin:0 0 12px; font-size:16px; color:#c8d6f7; }
    .setting { display:grid; grid-template-columns: minmax(220px, 1fr) minmax(260px, 1.3fr) auto; gap:12px; align-items:center; padding:10px 0; border-top:1px solid var(--line); }
    .setting:first-of-type { border-top:0; }
    .label { font-weight:700; }
    .key { color:var(--muted); font:12px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; margin-top:3px; }
    .muted { color:var(--muted); font-size:13px; }
    .badge { display:inline-block; border-radius:999px; padding:2px 8px; background:#1e2a46; border:1px solid var(--line); font-size:12px; }
    .badge.warn { color:var(--warn); }
    input[type="number"], input[type="text"] { width:100%; background:#080d19; border:1px solid var(--line); color:var(--text); border-radius:10px; padding:9px 10px; font:14px system-ui; }
    label.check { display:inline-flex; align-items:center; gap:7px; margin:4px 12px 4px 0; color:#c8d6f7; }
    input[type="checkbox"] { width:18px; height:18px; accent-color:#2563eb; }
    button, a.button { background:#2563eb; color:white; border:0; border-radius:10px; padding:8px 10px; font-weight:700; cursor:pointer; margin:2px; text-decoration:none; display:inline-block; }
    button:hover, a.button:hover { background:#1d4ed8; }
    button.secondary, a.button.secondary { background:#475569; }
    button.secondary:hover, a.button.secondary:hover { background:#334155; }
    button.danger { background:#b91c1c; }
    button.danger:hover { background:#991b1b; }
    #status { min-height:20px; }
    @media (max-width: 820px) { .setting { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
<header>
  <div class="row">
    <h1>Настройки Selectel Finder</h1>
    <div>
      <a class="button secondary" href="/dashboard">Dashboard</a>
      <button onclick="saveAll()">Сохранить</button>
      <button class="secondary" onclick="loadSettings()">Обновить</button>
    </div>
  </div>
  <div class="muted" id="status">загрузка...</div>
</header>
<main>
  <section class="group">
    <h2>Presets</h2>
    <button class="secondary" onclick="applyPreset('safe_ru3_ru7')">Безопасный ru-3/ru-7</button>
    <button class="secondary" onclick="applyPreset('fast_test')">Быстрый тест</button>
    <button class="secondary" onclick="applyPreset('reliable_provisioning')">Надежный provisioning</button>
    <button class="secondary" onclick="applyPreset('keep_failed_ip')">Сохранять failed IP</button>
  </section>
  <div id="settings"></div>
</main>
<script>
let settings = [];
function esc(s){return String(s ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));}
function inputHtml(s){
  if(s.kind === 'bool'){
    return `<label class="check"><input type="checkbox" id="s_${s.key}" ${s.value ? 'checked' : ''}> включено</label>`;
  }
  if(s.kind === 'regions'){
    return `<div>${(s.choices||[]).map(region => `<label class="check"><input type="checkbox" data-setting="${s.key}" value="${esc(region)}" ${(s.value||[]).includes(region) ? 'checked' : ''}>${esc(region)}</label>`).join('')}</div>`;
  }
  return `<input type="number" id="s_${s.key}" value="${esc(s.value)}" min="${esc(s.min ?? '')}" max="${esc(s.max ?? '')}">`;
}
function render(){
  const groups = {};
  for(const s of settings){ (groups[s.group] ||= []).push(s); }
  document.getElementById('settings').innerHTML = Object.entries(groups).map(([group, items]) => `
    <section class="group">
      <h2>${esc(group)}</h2>
      ${items.map(s => `
        <div class="setting">
          <div><div class="label">${esc(s.label)}</div><div class="key">${esc(s.key)}</div></div>
          <div>${inputHtml(s)}<div class="muted">env/default: ${Array.isArray(s.default) ? esc(s.default.join(', ')) : esc(s.default)}</div></div>
          <div><span class="badge ${s.overridden ? 'warn' : ''}">${s.overridden ? 'runtime' : 'env'}</span><br><button class="secondary" onclick="resetOne('${esc(s.key)}')">Сброс</button></div>
        </div>
      `).join('')}
    </section>
  `).join('');
}
function collectValue(s){
  if(s.kind === 'bool') return document.getElementById('s_'+s.key).checked;
  if(s.kind === 'regions') return [...document.querySelectorAll(`[data-setting="${s.key}"]:checked`)].map(item => item.value);
  return Number(document.getElementById('s_'+s.key).value);
}
async function loadSettings(){
  const r = await fetch('/dashboard/api/settings', {cache:'no-store'});
  const data = await r.json().catch(()=>({ok:false,error:'bad json'}));
  if(!r.ok || !data.ok){ document.getElementById('status').textContent = 'ошибка загрузки: ' + (data.error || r.status); return; }
  settings = data.settings || [];
  document.getElementById('status').textContent = 'обновлено: ' + new Date((data.generated_at||0)*1000).toLocaleString();
  render();
}
async function saveAll(){
  const values = {};
  for(const s of settings){ values[s.key] = collectValue(s); }
  const r = await fetch('/dashboard/api/settings', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({values})});
  const data = await r.json().catch(()=>({ok:false,error:'bad json'}));
  if(!r.ok || !data.ok){ alert('Ошибка: ' + (data.error || r.status)); return; }
  settings = data.settings || [];
  document.getElementById('status').textContent = 'сохранено: ' + new Date().toLocaleString();
  render();
}
async function resetOne(key){
  const r = await fetch('/dashboard/api/settings', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({reset:[key]})});
  const data = await r.json().catch(()=>({ok:false,error:'bad json'}));
  if(!r.ok || !data.ok){ alert('Ошибка: ' + (data.error || r.status)); return; }
  settings = data.settings || [];
  document.getElementById('status').textContent = 'сброшено: ' + key;
  render();
}
async function applyPreset(preset){
  if(!confirm('Применить preset: ' + preset + '?')) return;
  const r = await fetch('/dashboard/api/settings', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({preset})});
  const data = await r.json().catch(()=>({ok:false,error:'bad json'}));
  if(!r.ok || !data.ok){ alert('Ошибка: ' + (data.error || r.status)); return; }
  settings = data.settings || [];
  document.getElementById('status').textContent = 'preset применен: ' + preset;
  render();
}
loadSettings();
</script>
</body>
</html>"""


class TesterAPIHandler(BaseHTTPRequestHandler):
    server_version = "SelectelFinderTester/1.0"

    def log_message(self, fmt, *args):
        print(f"[tester-api] {self.address_string()} - {fmt % args}", flush=True)

    def _send_json(self, status: int, payload: dict):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_text(self, status: int, text: str, content_type: str = "text/plain; charset=utf-8"):
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_dashboard_login(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Selectel Finder Dashboard"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write("Dashboard login required".encode("utf-8"))

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def _authorized(self) -> bool:
        if not TESTER_TOKEN:
            return False
        return hmac.compare_digest(self.headers.get("X-Tester-Token", ""), TESTER_TOKEN)

    def _dashboard_authorized(self) -> bool:
        if not DASHBOARD_ENABLED or not DASHBOARD_PASSWORD:
            return False
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception:
            return False
        return hmac.compare_digest(username, DASHBOARD_USERNAME) and hmac.compare_digest(password, DASHBOARD_PASSWORD)

    def _require_dashboard_auth(self) -> bool:
        if not DASHBOARD_ENABLED:
            self._send_text(404, "dashboard disabled")
            return False
        if not DASHBOARD_PASSWORD:
            self._send_text(503, "DASHBOARD_PASSWORD is empty")
            return False
        if not self._dashboard_authorized():
            self._send_dashboard_login()
            return False
        return True

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send_json(200, {"ok": True, **get_tester_control_state(), "stats": get_vless_queue_stats()})
            return

        if parsed.path == "/dashboard":
            if not self._require_dashboard_auth():
                return
            self._send_text(200, dashboard_html(), "text/html; charset=utf-8")
            return

        if parsed.path == "/dashboard/settings":
            if not self._require_dashboard_auth():
                return
            self._send_text(200, dashboard_settings_html(), "text/html; charset=utf-8")
            return

        if parsed.path == "/dashboard/api/status":
            if not self._require_dashboard_auth():
                return
            self._send_json(200, dashboard_snapshot())
            return

        if parsed.path == "/dashboard/api/settings":
            if not self._require_dashboard_auth():
                return
            self._send_json(200, dashboard_settings_snapshot())
            return

        if parsed.path == "/dashboard/api/logs":
            if not self._require_dashboard_auth():
                return
            self._send_json(200, {"ok": True, "finder_log": tail_file_text(LOG_FILE, DASHBOARD_LOG_LINES), "workers": get_worker_statuses()})
            return

        if not self._authorized():
            self._send_json(401, {"ok": False, "error": "unauthorized"})
            return

        if parsed.path == "/next_tests":
            query = parse_qs(parsed.query)
            worker = (query.get("worker") or ["unknown-worker"])[0]
            limit_raw = (query.get("limit") or [str(tester_batch_size())])[0]
            try:
                limit = int(limit_raw)
            except ValueError:
                limit = tester_batch_size()
            if is_testing_paused():
                self._send_json(200, {"ok": True, "paused": True, "tasks": []})
                return
            tasks = reserve_vless_tests(worker=worker, limit=limit)
            self._send_json(200, {"ok": True, "paused": False, "tasks": tasks})
            return

        self._send_json(404, {"ok": False, "error": "not_found"})

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/dashboard/api/settings":
            if not self._require_dashboard_auth():
                return
            try:
                payload = self._read_json()
                preset = (payload.get("preset") or "").strip()
                if preset:
                    self._send_json(200, apply_runtime_preset(preset, actor=DASHBOARD_USERNAME))
                else:
                    self._send_json(200, update_runtime_settings(payload, actor=DASHBOARD_USERNAME))
            except Exception as e:
                print(f"[dashboard] settings error: {e}", flush=True)
                self._send_json(400, {"ok": False, "error": str(e)})
            return

        if parsed.path == "/dashboard/api/bulk_action":
            if not self._require_dashboard_auth():
                return
            try:
                payload = self._read_json()
                result = bulk_dashboard_action(payload, actor=DASHBOARD_USERNAME)
                result["stats"] = get_vless_queue_stats()
                self._send_json(200, result)
            except Exception as e:
                print(f"[dashboard] bulk action error: {e}", flush=True)
                self._send_json(400, {"ok": False, "error": str(e)})
            return

        if parsed.path == "/dashboard/api/action":
            if not self._require_dashboard_auth():
                return
            try:
                payload = self._read_json()
                action = (payload.get("action") or "").strip().lower()
                test_id = int(payload.get("id") or 0)
                if action == "retry":
                    result = start_manual_retry(test_id, actor=DASHBOARD_USERNAME)
                elif action == "delete":
                    result = manually_delete_vless_test(test_id, actor=DASHBOARD_USERNAME)
                else:
                    raise RuntimeError("unknown action")
                self._send_json(200, {"ok": True, "result": result, "stats": get_vless_queue_stats()})
            except Exception as e:
                print(f"[dashboard] action error: {e}", flush=True)
                self._send_json(400, {"ok": False, "error": str(e)})
            return

        if not self._authorized():
            self._send_json(401, {"ok": False, "error": "unauthorized"})
            return

        if parsed.path == "/worker_heartbeat":
            try:
                payload = self._read_json()
                worker = (payload.get("worker") or "unknown-worker")[:80]
                saved = save_worker_heartbeat(payload, worker=worker)
                self._send_json(200, {"ok": True, "saved": saved})
            except Exception as e:
                print(f"[tester-api] POST /worker_heartbeat error: {e}", flush=True)
                self._send_json(400, {"ok": False, "error": str(e)})
            return

        if parsed.path != "/results":
            self._send_json(404, {"ok": False, "error": "not_found"})
            return

        try:
            payload = self._read_json()
            worker = (payload.get("worker") or "unknown-worker")[:80]
            results = payload.get("results") or []
            if not isinstance(results, list):
                raise RuntimeError("results must be a list")
            saved = [complete_vless_test_result(item, worker=worker) for item in results]
            save_worker_heartbeat({"worker": worker, "api_ok": True, "control_ok": True, "current_task": "", "last_error": "", "log_tail": ""}, worker=worker)
            self._send_json(200, {"ok": True, "saved": saved, "stats": get_vless_queue_stats()})
        except Exception as e:
            print(f"[tester-api] POST /results error: {e}", flush=True)
            self._send_json(400, {"ok": False, "error": str(e)})


def start_tester_api_if_enabled():
    global tester_api_server

    init_vless_queue()

    if not TESTER_API_ENABLED:
        print("[tester-api] disabled: TESTER_API_ENABLED=false", flush=True)
        return
    if not TESTER_TOKEN:
        print("[tester-api] disabled: TESTER_TOKEN is empty", flush=True)
        send(TELEGRAM_ALLOWED_CHAT_ID, "⚠️ API авто-тестера выключен: TESTER_TOKEN пустой")
        return

    try:
        tester_api_server = ThreadingHTTPServer((TESTER_API_HOST, TESTER_API_PORT), TesterAPIHandler)
        thread = threading.Thread(target=tester_api_server.serve_forever, daemon=True)
        thread.start()
        print(f"[tester-api] listening on {TESTER_API_HOST}:{TESTER_API_PORT}", flush=True)
        if DASHBOARD_ENABLED:
            print(f"[dashboard] enabled on /dashboard user={DASHBOARD_USERNAME}", flush=True)
        send(TELEGRAM_ALLOWED_CHAT_ID, f"📲 API авто-тестера запущен: {TESTER_API_HOST}:{TESTER_API_PORT}")
    except Exception as e:
        tester_api_server = None
        print(f"[tester-api] failed to start: {e}", flush=True)
        send(TELEGRAM_ALLOWED_CHAT_ID, f"⚠️ API авто-тестера не запустился: {e}")

# =========================
# PROVISIONING
# =========================

def find_floating_ip(conn, address: str):
    for ip in conn.network.ips():
        if getattr(ip, "floating_ip_address", "") == address:
            return ip
    return None


def delete_floating_ip_address(conn, address: str, ip_id: str = ""):
    target = ip_id or None
    if not target:
        ip = find_floating_ip(conn, address)
        target = getattr(ip, "id", None) if ip else None

    if target:
        delete_floating_ip(conn, target)


def cleanup_failed_floating_ip_if_enabled(conn, record: GoodIpRecord):
    if not provision_delete_failed_floating_ip():
        return
    try:
        delete_floating_ip_address(conn, record.ip, record.ip_id)
        remove_good_ip(record.ip)
        print(f"Deleted failed floating IP after provisioning failure: {record.ip}", flush=True)
    except Exception as e:
        print(f"Failed to delete floating IP after provisioning failure for {record.ip}: {e}", flush=True)


def get_server_ports(conn, server_id: str):
    """Return Neutron ports attached to a server."""
    return list(conn.network.ports(device_id=server_id))


def attach_floating_ip_to_server(conn, server, floating_ip_address: str):
    """Attach floating IP through Neutron instead of Nova server action.

    Selectel may return 404 for Nova /servers/<id>/action when using
    conn.compute.add_floating_ip_to_server(). Updating the floating IP port_id
    through Neutron is more reliable.
    """
    server_id = getattr(server, "id", "")
    if not server_id:
        raise RuntimeError("Server has no id, cannot attach floating IP")

    ports = get_server_ports(conn, server_id)
    if not ports:
        raise RuntimeError(f"No Neutron ports found for server {server_id}")

    port = ports[0]
    floating_ip = find_floating_ip(conn, floating_ip_address)
    if not floating_ip:
        raise RuntimeError(f"Floating IP not found: {floating_ip_address}")

    conn.network.update_ip(floating_ip, port_id=port.id)
    print(
        f"✅ Floating IP привязан через Neutron: {floating_ip_address} -> port {port.id}",
        flush=True,
    )


def detach_floating_ip_from_server(conn, floating_ip_address: str):
    """Detach floating IP through Neutron."""
    floating_ip = find_floating_ip(conn, floating_ip_address)
    if not floating_ip:
        return

    if getattr(floating_ip, "port_id", None):
        conn.network.update_ip(floating_ip, port_id=None)
        print(f"✅ Floating IP отвязан через Neutron: {floating_ip_address}", flush=True)


def provision_region_env(name: str, region: str) -> str:
    return region_env(f"PROVISION_{name}", region)


def get_provision_image(conn, region):
    image_id = provision_region_env("IMAGE_ID", region) or PROVISION_IMAGE_ID
    image_name = provision_region_env("IMAGE_NAME", region) or PROVISION_IMAGE_NAME

    if image_id:
        image = conn.image.find_image(image_id, ignore_missing=True)
        if image:
            return image
        raise RuntimeError(f"Ubuntu image id not found in {region}: {image_id}")

    if image_name:
        image = conn.image.find_image(image_name, ignore_missing=True)
        if image:
            return image

    images = [
        image
        for image in conn.image.images()
        if getattr(image, "status", "") == "active"
        and "ubuntu" in (getattr(image, "name", "") or "").lower()
    ]

    preferred = ["ubuntu 24.04 lts 64-bit", "ubuntu 22.04 lts 64-bit", "ubuntu 20.04 lts 64-bit"]
    for expected_name in preferred:
        for image in images:
            if (getattr(image, "name", "") or "").lower() == expected_name:
                return image

    if images:
        images.sort(key=lambda image: getattr(image, "name", "") or "")
        return images[0]

    raise RuntimeError(f"No active Ubuntu image found in {region}")


def flavor_sort_key(flavor):
    return (
        getattr(flavor, "vcpus", 10**9) or 10**9,
        getattr(flavor, "ram", 10**9) or 10**9,
        getattr(flavor, "disk", 10**9) or 10**9,
        str(getattr(flavor, "name", "")),
    )


def get_candidate_flavors(conn, region):
    """Return flavors to try, ordered from smallest to larger ones.

    If PROVISION_FLAVOR_ID/NAME or regional override is set, that flavor is tried first.
    When PROVISION_AUTO_FLAVOR_FALLBACK=true, the bot also tries other suitable flavors
    if the selected one is rejected by Selectel.
    """
    flavor_id = provision_region_env("FLAVOR_ID", region) or PROVISION_FLAVOR_ID
    flavor_name = provision_region_env("FLAVOR_NAME", region) or PROVISION_FLAVOR_NAME
    selected_flavor = None

    if flavor_id:
        selected_flavor = conn.compute.find_flavor(flavor_id, ignore_missing=True)
        if not selected_flavor:
            raise RuntimeError(f"Flavor id not found in {region}: {flavor_id}")

    if flavor_name and not selected_flavor:
        selected_flavor = conn.compute.find_flavor(flavor_name, ignore_missing=True)
        if not selected_flavor:
            raise RuntimeError(f"Flavor not found in {region}: {flavor_name}")

    flavors = list(conn.compute.flavors())
    if PROVISION_REQUIRE_LOCAL_DISK:
        flavors = [flavor for flavor in flavors if (getattr(flavor, "disk", 0) or 0) > 0]

    if selected_flavor:
        selected_id = getattr(selected_flavor, "id", "")
        rest = [flavor for flavor in flavors if getattr(flavor, "id", "") != selected_id]
        rest.sort(key=flavor_sort_key)
        flavors = [selected_flavor] + (rest if PROVISION_AUTO_FLAVOR_FALLBACK else [])
    else:
        flavors.sort(key=flavor_sort_key)

    if not flavors:
        raise RuntimeError(f"No suitable flavors found in {region}")

    return flavors[:provision_max_flavor_attempts()]


def get_provision_flavor(conn, region):
    return get_candidate_flavors(conn, region)[0]

def get_provision_network(conn, region):
    network_id = provision_region_env("NETWORK_ID", region) or PROVISION_NETWORK_ID
    network_name = provision_region_env("NETWORK_NAME", region) or PROVISION_NETWORK_NAME

    if network_id:
        network = conn.network.find_network(network_id, ignore_missing=True)
        if network:
            return network
        raise RuntimeError(f"Network id not found in {region}: {network_id}")

    if network_name:
        network = conn.network.find_network(network_name, ignore_missing=True)
        if network:
            return network
        raise RuntimeError(f"Network not found in {region}: {network_name}")

    networks = [
        network
        for network in conn.network.networks()
        if not getattr(network, "is_router_external", False)
    ]

    if not networks:
        raise RuntimeError(f"No private network found in {region}; set PROVISION_NETWORK_ID")

    networks.sort(key=lambda network: getattr(network, "name", "") or "")
    return networks[0]


def get_explicit_provision_availability_zone(region):
    """Return only the explicitly configured availability zone.

    Selectel may reject a flavor when an automatically selected AZ is unsuitable.
    Therefore the bot does not auto-pick AZ anymore; if this value is empty,
    OpenStack/Selectel chooses a suitable zone itself.
    """
    return provision_region_env("AVAILABILITY_ZONE", region) or PROVISION_AVAILABILITY_ZONE

def ensure_security_group(conn):
    security_group = conn.network.find_security_group(PROVISION_SECURITY_GROUP, ignore_missing=True)
    if not security_group:
        security_group = conn.network.create_security_group(
            name=PROVISION_SECURITY_GROUP,
            description="Selectel finder temporary VLESS test access",
        )

    for rule in conn.network.security_group_rules(security_group_id=security_group.id):
        if (
            getattr(rule, "direction", "") == "ingress"
            and str(getattr(rule, "protocol", "")).lower() == "tcp"
            and getattr(rule, "port_range_min", None) == 443
            and getattr(rule, "port_range_max", None) == 443
            and getattr(rule, "remote_ip_prefix", None) in (None, "0.0.0.0/0")
        ):
            return security_group

    try:
        conn.network.create_security_group_rule(
            security_group_id=security_group.id,
            direction="ingress",
            ethertype="IPv4",
            protocol="tcp",
            port_range_min=443,
            port_range_max=443,
            remote_ip_prefix="0.0.0.0/0",
        )
    except Exception as e:
        print(f"⚠️ Не удалось создать security group rule TCP/443: {e}", flush=True)

    return security_group


def make_cloud_init_script() -> str:
    return (
        "#!/bin/bash\n"
        "set -euxo pipefail\n"
        "export DEBIAN_FRONTEND=noninteractive\n"
        "apt-get update\n"
        "apt-get install -y curl\n"
        "cd /root\n"
        "curl -fsSLO https://raw.githubusercontent.com/denpiligrim/3dp-manager/main/forwarding_install.sh\n"
        f"export ORIGIN_IP=\"{PROVISION_ORIGIN_IP}\"\n"
        "sudo -E bash forwarding_install.sh\n"
    )


def make_vless_key(ip: str) -> str:
    return (
        PROVISION_VLESS_TEMPLATE
        .replace("{Белый IP}", ip)
        .replace("{WHITE_IP}", ip)
        .replace("{IP}", ip)
        .replace("{ip}", ip)
    )


def validate_provision_config():
    missing = []

    if not PROVISION_ORIGIN_IP:
        missing.append("PROVISION_ORIGIN_IP")
    if not PROVISION_VLESS_TEMPLATE:
        missing.append("PROVISION_VLESS_TEMPLATE")
    elif not any(token in PROVISION_VLESS_TEMPLATE for token in ("{WHITE_IP}", "{Белый IP}", "{IP}", "{ip}")):
        raise RuntimeError("PROVISION_VLESS_TEMPLATE must contain {WHITE_IP}")

    if missing:
        raise RuntimeError(f"Missing provisioning settings: {', '.join(missing)}")


def tcp_connect_ok(host: str, port: int = 443, timeout: int = 5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_tcp_port(host: str, port: int = 443) -> bool:
    if not provision_tcp_check_enabled():
        return True
    retries = max(1, provision_tcp_check_retries())
    timeout = max(1, provision_tcp_check_timeout())
    for attempt in range(1, retries + 1):
        if tcp_connect_ok(host, port=port, timeout=timeout):
            print(f"✅ TCP/{port} открыт на {host}", flush=True)
            return True
        print(f"⏳ TCP/{port} пока закрыт на {host}, попытка {attempt}/{retries}", flush=True)
        if attempt < retries:
            time.sleep(5)
    return False


def create_test_server(conn, record: GoodIpRecord):
    region = record.region
    preemptible = region in provision_preemptible_regions()
    if not region_can_provision(region):
        raise RuntimeError(region_provision_block_reason(region))

    image = get_provision_image(conn, region)
    flavors = get_candidate_flavors(conn, region)
    network = get_provision_network(conn, region)
    security_group = ensure_security_group(conn)
    availability_zone = get_explicit_provision_availability_zone(region)
    user_data = base64.b64encode(make_cloud_init_script().encode("utf-8")).decode("ascii")

    base_attrs = {
        "image_id": image.id,
        "networks": [{"uuid": network.id}],
        "security_groups": [{"name": security_group.name}],
        "user_data": user_data,
        "metadata": {"selectel_finder_ip": record.ip},
    }

    if availability_zone:
        base_attrs["availability_zone"] = availability_zone
    if PROVISION_KEY_NAME:
        base_attrs["key_name"] = PROVISION_KEY_NAME
    if preemptible:
        base_attrs["tags"] = ["preemptible"]

    last_error = None

    for index, flavor in enumerate(flavors, 1):
        server = None
        server_name = (
            f"{PROVISION_SERVER_NAME_PREFIX}-{region}-{record.ip.replace('.', '-')}-"
            f"{int(time.time())}-{index}"
        )
        attrs = dict(base_attrs)
        attrs["name"] = server_name
        attrs["flavor_id"] = flavor.id

        print(
            f"🚀 Пробую сервер {server_name}: region={region}, "
            f"image={getattr(image, 'name', image.id)}, "
            f"flavor={getattr(flavor, 'name', flavor.id)}, "
            f"network={getattr(network, 'name', network.id)}, "
            f"preemptible={preemptible}, "
            f"availability_zone={availability_zone or 'auto'}, "
            f"attempt={index}/{len(flavors)}",
            flush=True,
        )

        try:
            server = conn.compute.create_server(**attrs)
            server = conn.compute.wait_for_server(server, wait=provision_server_wait_seconds())
            attach_floating_ip_to_server(conn, server, record.ip)

            print(
                f"✅ Сервер создан: {server_name}, "
                f"flavor={getattr(flavor, 'name', flavor.id)}",
                flush=True,
            )

            setup_wait = provision_setup_wait_seconds()
            if setup_wait:
                time.sleep(setup_wait)

            return server

        except Exception as e:
            last_error = e
            flavor_name = getattr(flavor, "name", flavor.id)
            print(f"⚠️ Flavor не подошёл {flavor_name}: {e}", flush=True)

            if server:
                try:
                    cleanup_test_server(conn, getattr(server, "id", ""), record.ip)
                except Exception as cleanup_error:
                    print(f"⚠️ Cleanup после неудачной попытки не удался: {cleanup_error}", flush=True)

            continue

    raise RuntimeError(
        f"Не удалось создать сервер в {region} после {len(flavors)} попыток. "
        f"Последняя ошибка: {last_error}"
    )

def cleanup_test_server(conn, server_id: str, ip: str):
    if not server_id:
        return

    try:
        server = conn.compute.find_server(server_id, ignore_missing=True)
        if not server:
            return
        try:
            detach_floating_ip_from_server(conn, ip)
        except Exception as e:
            print(f"⚠️ Не удалось отвязать floating IP {ip}: {e}", flush=True)
        conn.compute.delete_server(server, ignore_missing=True)
        try:
            conn.compute.wait_for_delete(server, wait=120)
        except Exception as e:
            print(f"⚠️ Не дождался удаления сервера {server_id}: {e}", flush=True)
    except Exception as e:
        print(f"⚠️ Ошибка удаления временного сервера {server_id}: {e}", flush=True)


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
            skipped_regions += 1
            continue
        records.append(record)
        if len(records) >= slots_left:
            break

    if skipped_regions:
        send(
            TELEGRAM_ALLOWED_CHAT_ID,
            f"ℹ️ Пропущено IP из регионов без разрешенного provisioning: {skipped_regions}. "
            "Они помечены как provision_failed без автобана.",
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
    start_tester_api_if_enabled()

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
