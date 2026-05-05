import ipaddress
from dataclasses import dataclass
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
GOOD_IPS_FILE = BASE_DIR / "good_ips.txt"
BANNED_IPS_FILE = BASE_DIR / "banned_ips.txt"
APPROVED_KEYS_FILE = BASE_DIR / "approved_vless_keys.txt"
BANNED_IPV4_PREFIX = 24
MANAGED_LIST_MAX_BYTES = 2 * 1024 * 1024


@dataclass
class GoodIpRecord:
    ip: str
    region: str
    ip_id: str = ""


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


def save_good_ip(ip: str, region: str, ip_id: str):
    if is_banned_ip(ip):
        return

    records = load_good_ips()
    existing = {record.ip for record in records}

    if ip in existing:
        return

    with open(GOOD_IPS_FILE, "a", encoding="utf-8") as f:
        f.write(f"{ip} {region} id={ip_id}\n")


def banned_network_for_ip(ip: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    ip_obj = ipaddress.ip_address(ip)
    prefix = BANNED_IPV4_PREFIX if ip_obj.version == 4 else ip_obj.max_prefixlen
    return ipaddress.ip_network(f"{ip_obj}/{prefix}", strict=False)


def parse_banned_network(token: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    token = token.strip()
    if not token:
        return None
    try:
        if "/" in token:
            return ipaddress.ip_network(token, strict=False)
        return banned_network_for_ip(token)
    except ValueError:
        return None


def load_banned_ips() -> set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    if not BANNED_IPS_FILE.exists():
        return set()

    banned = set()
    with open(BANNED_IPS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            token = line.strip().split(maxsplit=1)[0] if line.strip() else ""
            network = parse_banned_network(token)
            if network:
                banned.add(network)

    return banned


def ip_in_banned_networks(ip: str, banned_networks) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(ip_obj in network for network in banned_networks)


def is_banned_ip(ip: str) -> bool:
    return ip_in_banned_networks(ip, load_banned_ips())


def ban_ip(ip: str, reason: str = ""):
    network = banned_network_for_ip(ip)
    banned = load_banned_ips()
    if network in banned:
        return

    with open(BANNED_IPS_FILE, "a", encoding="utf-8") as f:
        suffix = f" {reason}" if reason else ""
        f.write(f"{network}{suffix}\n")


def remove_good_ip(ip: str):
    records = [record for record in load_good_ips() if record.ip != ip]
    write_good_ips(records)


def remove_banned_good_ips():
    banned = load_banned_ips()
    records = [record for record in load_good_ips() if not ip_in_banned_networks(record.ip, banned)]
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


MANAGED_LIST_FILES = {
    "approved_vless_keys.txt": {
        "path": APPROVED_KEYS_FILE,
        "title": "Рабочие VLESS-ключи",
        "description": "IP, регион и собранный vless:// ключ",
    },
    "good_ips.txt": {
        "path": GOOD_IPS_FILE,
        "title": "Найденные IP",
        "description": "Кандидаты для проверки: IP, регион и optional id=...",
    },
    "banned_ips.txt": {
        "path": BANNED_IPS_FILE,
        "title": "Бан-лист IP",
        "description": "CIDR-подсети или IP, которые нельзя брать снова",
    },
}


def normalize_managed_list_name(name: str) -> str:
    raw = Path(str(name or "").replace("\\", "/")).name.strip()
    if raw in MANAGED_LIST_FILES:
        return raw
    if raw and f"{raw}.txt" in MANAGED_LIST_FILES:
        return f"{raw}.txt"
    raise RuntimeError("неизвестный список")


def managed_list_path(name: str) -> Path:
    return MANAGED_LIST_FILES[normalize_managed_list_name(name)]["path"]


def validate_managed_list_content(name: str, content: str):
    name = normalize_managed_list_name(name)
    size = len(content.encode("utf-8"))
    if size > MANAGED_LIST_MAX_BYTES:
        raise RuntimeError(f"файл слишком большой: {size} байт")

    errors = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        try:
            if name == "good_ips.txt":
                if len(parts) < 2:
                    raise ValueError("ожидается: IP регион [id=...]")
                ipaddress.ip_address(parts[0])
            elif name == "approved_vless_keys.txt":
                if len(parts) < 3:
                    raise ValueError("ожидается: IP регион vless://...")
                ipaddress.ip_address(parts[0])
                if not parts[2].startswith("vless://"):
                    raise ValueError("третья колонка должна начинаться с vless://")
            elif name == "banned_ips.txt":
                if not parse_banned_network(parts[0]):
                    raise ValueError("ожидается IP или CIDR")
        except ValueError as exc:
            errors.append(f"строка {line_no}: {exc}")
            if len(errors) >= 8:
                break

    if errors:
        suffix = "" if len(errors) < 8 else "; ..."
        raise RuntimeError("ошибка в списке: " + "; ".join(errors) + suffix)


def read_managed_list(name: str) -> dict:
    name = normalize_managed_list_name(name)
    spec = MANAGED_LIST_FILES[name]
    path = spec["path"]
    content = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    return {
        "ok": True,
        "name": name,
        "title": spec["title"],
        "description": spec["description"],
        "content": content,
        "bytes": len(content.encode("utf-8")),
        "lines": len([line for line in content.splitlines() if line.strip()]),
        "updated_at": int(path.stat().st_mtime) if path.exists() else 0,
    }


def managed_lists_snapshot() -> list[dict]:
    items = []
    for name in MANAGED_LIST_FILES:
        item = read_managed_list(name)
        item.pop("content", None)
        items.append(item)
    return items


def save_managed_list(name: str, content: str) -> dict:
    name = normalize_managed_list_name(name)
    if not isinstance(content, str):
        raise RuntimeError("содержимое должно быть строкой")
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    if normalized and not normalized.endswith("\n"):
        normalized += "\n"
    validate_managed_list_content(name, normalized)

    path = managed_list_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_file = path.with_name(path.name + ".tmp")
    with open(temp_file, "w", encoding="utf-8") as f:
        f.write(normalized)
    temp_file.replace(path)

    return read_managed_list(name)
