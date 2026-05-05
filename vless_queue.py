import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

from lists_store import GoodIpRecord


BASE_DIR = Path(__file__).resolve().parent
VLESS_QUEUE_DB = BASE_DIR / "vless_tests.sqlite3"
vless_queue_lock = threading.RLock()
_redact_text: Callable[[str], str] = lambda value: str(value or "")

IP_NOT_SUITABLE_STATUSES = {"ip_not_suitable", "phone_tcp_unreachable"}
PHONE_FAILURE_STATUSES = {"ip_not_suitable", "phone_tcp_unreachable", "vless_failed", "exit_ip_mismatch", "phone_failed"}
FINAL_VLESS_STATUSES = {"approved", "provision_failed", "manual_banned", "deleted", "rejected", "error", *PHONE_FAILURE_STATUSES}
ACTIVE_VLESS_STATUSES = {"queued", "testing", "provisioning"}
REVIEW_VLESS_STATUSES = {"provision_failed", "error", "rejected", *PHONE_FAILURE_STATUSES}
CONTROL_DEFAULTS = {
    "testing_paused": "0",
    "provisioning_paused": "0",
    "full_auto_mode": "0",
}


def configure_vless_queue(db_path: Path | str | None = None, redactor: Callable[[str], str] | None = None):
    global VLESS_QUEUE_DB, _redact_text
    if db_path:
        VLESS_QUEUE_DB = Path(db_path)
    if redactor:
        _redact_text = redactor


def redact_text(value) -> str:
    return _redact_text(str(value or ""))


def now_ts() -> int:
    return int(time.time())


@contextmanager
def get_vless_queue_conn():
    VLESS_QUEUE_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(VLESS_QUEUE_DB, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


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


def get_tester_control_raw(key: str) -> str | None:
    init_vless_queue()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        row = conn.execute("SELECT value FROM tester_control WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else None


def get_tester_control_value(key: str, default: str = "0") -> str:
    raw = get_tester_control_raw(key)
    return raw if raw is not None else default


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


def delete_tester_control_value(key: str):
    init_vless_queue()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        conn.execute("DELETE FROM tester_control WHERE key = ?", (key,))


def is_testing_paused() -> bool:
    return get_tester_control_value("testing_paused") == "1"


def is_provisioning_paused() -> bool:
    return get_tester_control_value("provisioning_paused") == "1"


def is_full_auto_mode_enabled() -> bool:
    return get_tester_control_value("full_auto_mode") == "1"


def set_testing_paused(paused: bool):
    set_tester_control_value("testing_paused", "1" if paused else "0")


def set_provisioning_paused(paused: bool):
    set_tester_control_value("provisioning_paused", "1" if paused else "0")


def set_full_auto_mode(enabled: bool):
    set_tester_control_value("full_auto_mode", "1" if enabled else "0")


def get_tester_control_state() -> dict:
    return {
        "testing_paused": is_testing_paused(),
        "provisioning_paused": is_provisioning_paused(),
        "full_auto_mode": is_full_auto_mode_enabled(),
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


def load_blocking_vless_ips() -> set[str]:
    init_vless_queue()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        rows = conn.execute(
            """
            SELECT ip
            FROM vless_tests
            WHERE status NOT IN ('deleted', 'manual_banned')
            """
        ).fetchall()
    return {str(row["ip"]) for row in rows if row["ip"]}


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


def mark_provision_failed(record: GoodIpRecord, error: str, server_id: str, vless_key: str) -> int | None:
    init_vless_queue()
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


def mark_test_provisioning(test_id: int):
    init_vless_queue()
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


def mark_test_manual_banned(test_id: int, error: str):
    init_vless_queue()
    with vless_queue_lock, get_vless_queue_conn() as conn:
        conn.execute(
            """
            UPDATE vless_tests
            SET status = 'manual_banned', worker = NULL, error = ?, reserved_at = NULL, tested_at = ?
            WHERE id = ?
            """,
            ((error or "manual dashboard delete")[:1000], now_ts(), int(test_id)),
        )


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


def mark_region_tests_provision_failed(region: str, error: str) -> int:
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
        return int(cur.rowcount or 0)


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


def region_status_rows() -> tuple[list[dict], list[dict]]:
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
    return [dict(row) for row in rows], [dict(row) for row in last_rows]


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


def reserve_vless_tests(worker: str, limit: int, batch_size: int, max_attempts: int, lease_seconds: int) -> list[dict]:
    init_vless_queue()
    worker = (worker or "unknown-worker")[:80]
    limit = max(1, min(int(limit or batch_size), batch_size))
    now = now_ts()
    stale_before = now - lease_seconds

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


def get_active_vless_tests(limit: int = 80) -> list[dict]:
    init_vless_queue()
    limit = max(1, min(int(limit or 80), 200))
    statuses = sorted(ACTIVE_VLESS_STATUSES)
    placeholders = ",".join("?" for _ in statuses)
    with vless_queue_lock, get_vless_queue_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT id, ip, region, status, attempts, worker, exit_ip, direct_ip,
                   latency_ms, error, vless_key, server_id, created_at, reserved_at, tested_at
            FROM vless_tests
            WHERE status IN ({placeholders})
            ORDER BY
                CASE status
                    WHEN 'testing' THEN 0
                    WHEN 'queued' THEN 1
                    WHEN 'provisioning' THEN 2
                    ELSE 3
                END,
                COALESCE(reserved_at, tested_at, created_at) DESC
            LIMIT ?
            """,
            (*statuses, limit),
        ).fetchall()
        tests = []
        for row in rows:
            item = dict(row)
            item["error"] = redact_text(item.get("error") or "")
            item["display_status"] = "ip_not_suitable" if item.get("status") in IP_NOT_SUITABLE_STATUSES else item.get("status")
            tests.append(item)
        return tests


def save_vless_test_result(result: dict, worker: str, classify_failure: Callable[[str], str]) -> dict:
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
            final_status = classify_failure(error)
            conn.execute(
                """
                UPDATE vless_tests
                SET status = ?, worker = COALESCE(?, worker), exit_ip = ?, direct_ip = ?,
                    latency_ms = ?, error = ?, reserved_at = NULL, tested_at = ?
                WHERE id = ?
                """,
                (final_status, worker or None, exit_ip, direct_ip, latency_ms, error or "phone test failed", now, test_id),
            )

    return {
        "id": test_id,
        "saved": True,
        "status": final_status,
        "record": record,
        "server_id": server_id,
        "vless_key": vless_key,
        "latency_ms": latency_ms,
        "error": error,
    }
