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
PROVISION_DECISION_TIMEOUT = int_env("PROVISION_DECISION_TIMEOUT", 300)
PROVISION_DELETE_SERVER_AFTER_RESULT = bool_env("PROVISION_DELETE_SERVER_AFTER_RESULT", True)
PROVISION_DELETE_FAILED_FLOATING_IP = bool_env("PROVISION_DELETE_FAILED_FLOATING_IP", True)

running = False
last_good_ip_sync = 0.0
settings_version = 0
settings_lock = threading.RLock()
selected_regions = REGIONS.copy()
waiting_for_whitelist_file = False
provisioning_running = False
provisioning_lock = threading.RLock()
pending_vless_tests = {}
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


def allowed(message) -> bool:
    return str(message.chat.id) == str(TELEGRAM_ALLOWED_CHAT_ID)


def send(chat_id, text, reply_markup=None):
    try:
        bot.send_message(chat_id, text, reply_markup=reply_markup)
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
    if approved >= TARGET_COUNT:
        bot.reply_to(message, f"✅ Уже есть {approved}/{TARGET_COUNT} рабочих ключей. Добор не нужен.")
        return

    if left_to_find <= 0:
        bot.reply_to(
            message,
            "✅ Кандидаты уже набраны. Поиск не нужен.\n"
            f"✅ Принято ключей: {approved}/{TARGET_COUNT}\n"
            f"📦 Найдено кандидатов: {existing_candidates}/{TARGET_COUNT - approved}\n\n"
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
        f"✅ Принято ключей: {approved}/{TARGET_COUNT}\n"
        f"📦 Уже найдено кандидатов: {existing_candidates}/{TARGET_COUNT - approved}\n"
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
    slots_left = max(TARGET_COUNT - approved, 0)
    count = sync_good_ips(networks, exclude_approved=True)
    left_to_find = max(slots_left - count, 0)
    state = "работает" if running else "остановлен"
    fs = get_finder_state()

    with provisioning_lock:
        provision_state = "идет" if provisioning_running else "ожидает"

    bot.reply_to(
        message,
        f"📊 Статус: {state}\n"
        f"🔁 Попытка: {fs.get('current_attempt') or 0}\n"
        f"🌍 Текущий регион: {fs.get('current_region') or '-'}\n"
        f"🌐 Последний IP: {fs.get('last_ip') or '-'}\n"
        f"⚠️ Последняя ошибка: {fs.get('last_error') or '-'}\n"
        f"🕒 Запущен: {fs.get('started_at') or '-'}\n"
        f"✅ Принято ключей: {approved}/{TARGET_COUNT}\n"
        f"📦 Найдено кандидатов: {count}/{slots_left}\n"
        f"🔎 Осталось найти IP: {left_to_find}\n"
        f"🎯 Целей в файле: {whitelist_status}\n"
        f"🌍 Регионы: {format_regions()}\n"
        f"🧪 Создание серверов: {provision_state}\n"
        f"🚫 Бан-лист: {len(load_banned_ips())}"
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
        f"✅ Принято ключей: {approved_count()}/{TARGET_COUNT}\n"
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
    return max(TARGET_COUNT - approved_count(), 0)


def remaining_ips_to_find(networks=None) -> tuple[int, int, int]:
    """Return (approved, candidates, left_to_find).

    TARGET_COUNT is the final number of working keys.
    good_ips.txt contains candidates that have already been found but not yet checked.
    Therefore finder should search only: TARGET_COUNT - approved - candidates.
    """
    approved = approved_count()
    candidates = count_matching_good_ips(networks, exclude_approved=True)
    left_to_find = max(TARGET_COUNT - approved - candidates, 0)
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

    return flavors[:PROVISION_MAX_FLAVOR_ATTEMPTS]


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


def create_test_server(conn, record: GoodIpRecord):
    region = record.region
    preemptible = region in PROVISION_PREEMPTIBLE_REGIONS
    if not preemptible and not PROVISION_ALLOW_NON_PREEMPTIBLE:
        raise RuntimeError(
            f"Preemptible servers are not available in {region}; "
            "set PROVISION_ALLOW_NON_PREEMPTIBLE=true to use regular servers there"
        )

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
            server = conn.compute.wait_for_server(server, wait=PROVISION_SERVER_WAIT_SECONDS)
            conn.compute.add_floating_ip_to_server(server, record.ip)

            print(
                f"✅ Сервер создан: {server_name}, "
                f"flavor={getattr(flavor, 'name', flavor.id)}",
                flush=True,
            )

            if PROVISION_SETUP_WAIT_SECONDS:
                time.sleep(PROVISION_SETUP_WAIT_SECONDS)

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
            conn.compute.remove_floating_ip_from_server(server, ip)
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
    keyboard = types.InlineKeyboardMarkup(row_width=2)
    keyboard.add(
        types.InlineKeyboardButton("✅ Работает", callback_data=f"vless:ok:{token}"),
        types.InlineKeyboardButton("❌ Не работает", callback_data=f"vless:bad:{token}"),
    )
    return keyboard


def run_single_vless_test(record: GoodIpRecord):
    conn = get_connection(record.region)
    server = None
    token = secrets.token_urlsafe(8)
    vless_key = make_vless_key(record.ip)

    try:
        server = create_test_server(conn, record)
        pending = PendingVlessTest(
            token=token,
            record=record,
            server_id=server.id,
            vless_key=vless_key,
        )

        with provisioning_lock:
            pending_vless_tests[token] = pending

        send(
            TELEGRAM_ALLOWED_CHAT_ID,
            "🧪 Проверь ключ\n"
            f"IP: {record.ip}\n"
            f"Регион: {record.region}\n\n"
            f"{vless_key}",
            reply_markup=vless_keyboard(token),
        )

        if not pending.event.wait(PROVISION_DECISION_TIMEOUT):
            send(TELEGRAM_ALLOWED_CHAT_ID, f"⏱ Нет ответа по {record.ip}, временный сервер будет удален")
            return

        if pending.result == "ok":
            save_approved_key(record, vless_key)
            send(TELEGRAM_ALLOWED_CHAT_ID, f"✅ IP принят: {record.ip}")
        elif pending.result == "bad":
            ban_ip(record.ip, f"failed_vless_test region={record.region}")
            remove_good_ip(record.ip)
            if PROVISION_DELETE_FAILED_FLOATING_IP:
                delete_floating_ip_address(conn, record.ip, record.ip_id)
            send(TELEGRAM_ALLOWED_CHAT_ID, f"🚫 IP забанен: {record.ip}")

    except Exception as e:
        send(TELEGRAM_ALLOWED_CHAT_ID, f"⚠️ Ошибка проверки {record.ip} ({record.region}): {e}")
        print(f"⚠️ Provisioning error for {record.ip}: {e}", flush=True)
    finally:
        with provisioning_lock:
            pending_vless_tests.pop(token, None)

        if server and PROVISION_DELETE_SERVER_AFTER_RESULT:
            cleanup_test_server(conn, server.id, record.ip)

        close_connection(conn)


def provisioning_worker(records: list[GoodIpRecord]):
    global provisioning_running

    try:
        send(TELEGRAM_ALLOWED_CHAT_ID, f"🧪 Запускаю проверку VLESS для {len(records)} IP")

        for record in records:
            if is_banned_ip(record.ip):
                continue
            run_single_vless_test(record)

        send(TELEGRAM_ALLOWED_CHAT_ID, "✅ Проверка VLESS завершена")
    finally:
        with provisioning_lock:
            provisioning_running = False


def start_provisioning_if_needed(networks=None):
    global provisioning_running

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
        send(TELEGRAM_ALLOWED_CHAT_ID, f"✅ Уже есть {approved_count()}/{TARGET_COUNT} рабочих ключей")
        return

    records = matching_good_ip_records(networks, exclude_approved=True)[:slots_left]
    if not records:
        send(TELEGRAM_ALLOWED_CHAT_ID, "⚠️ Нет подходящих IP для VLESS-проверки")
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
                print(f"🎯 Все слоты заполнены: {approved_count()}/{TARGET_COUNT}", flush=True)
                running = False
                send(TELEGRAM_ALLOWED_CHAT_ID, f"🎯 Все слоты заполнены: {approved_count()}/{TARGET_COUNT}")
                time.sleep(5)
                continue

            if now - last_good_ip_sync >= GOOD_IP_SYNC_INTERVAL:
                current_count = sync_good_ips(whitelist, exclude_approved=True)
                last_good_ip_sync = now
            else:
                current_count = count_matching_good_ips(whitelist, exclude_approved=True)

            if current_count >= slots_left:
                print(
                    f"🎯 Кандидаты для свободных слотов найдены: {current_count}/{slots_left}; "
                    f"принято {approved_count()}/{TARGET_COUNT}",
                    flush=True,
                )
                running = False
                send(
                    TELEGRAM_ALLOWED_CHAT_ID,
                    "🎯 Кандидаты для свободных слотов найдены\n"
                    f"✅ Принято ключей: {approved_count()}/{TARGET_COUNT}\n"
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
            print(f"✅ Принято: {approved_count()}/{TARGET_COUNT}", flush=True)
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
                        f"✅ Принято ключей: {approved_count()}/{TARGET_COUNT}\n"
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
