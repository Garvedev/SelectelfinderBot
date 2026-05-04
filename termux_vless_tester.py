#!/usr/bin/env python3
"""Redmi/Termux worker for Selectel Finder Bot.

Control channel:
  CONTROL_VLESS -> sing-box on 127.0.0.1:20808 -> API /next_tests and /results

Test channel:
  candidate VLESS -> sing-box on 127.0.0.1:20809 -> curl https://api.ipify.org
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path
from collections import deque
from urllib.parse import parse_qs, unquote, urlparse

API_BASE = os.getenv("TESTER_API_BASE", "http://YOUR_VPS_IP:8787").rstrip("/")
TOKEN = os.getenv("TESTER_TOKEN", "")
WORKER_ID = os.getenv("WORKER_ID", "redmi-a9")
CONTROL_VLESS = os.getenv("CONTROL_VLESS", "")

WORK_DIR = Path(os.getenv("TESTER_WORK_DIR", str(Path.home() / "selectel-tester")))
CONTROL_CONFIG = WORK_DIR / "singbox-control.json"
TEST_CONFIG = WORK_DIR / "singbox-test.json"
PENDING_RESULTS = WORK_DIR / "pending_results.jsonl"

CONTROL_PORT = int(os.getenv("CONTROL_PROXY_PORT", "20808"))
TEST_PORT = int(os.getenv("TEST_PROXY_PORT", "20809"))
BATCH_SIZE = int(os.getenv("TESTER_BATCH_SIZE", "11"))
POLL_SLEEP = int(os.getenv("POLL_SLEEP", "10"))
SINGBOX_STARTUP_WAIT = float(os.getenv("SINGBOX_STARTUP_WAIT", "2.5"))
CURL_TIMEOUT = int(os.getenv("CURL_TIMEOUT", "20"))
TEST_URL = os.getenv("TEST_URL", "https://api.ipify.org")
DIRECT_TEST_URL = os.getenv("DIRECT_TEST_URL", TEST_URL)
HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL", "30"))
AGENT_VERSION = "dashboard-1"

LOG_BUFFER: deque[str] = deque(maxlen=80)


def log(message: str):
    line = time.strftime("%Y-%m-%d %H:%M:%S") + " " + message
    LOG_BUFFER.append(line)
    print(line, flush=True)


def first(params: dict[str, list[str]], name: str, default: str | None = None):
    value = params.get(name)
    if not value:
        return default
    return value[0]


def parse_vless_url(vless_url: str) -> dict:
    u = urlparse(vless_url)
    if u.scheme != "vless":
        raise ValueError("not a vless:// URL")

    params = parse_qs(u.query)
    uuid = unquote(u.username or "")
    server = u.hostname
    port = u.port or 443
    network = first(params, "type", "tcp")
    security = first(params, "security", "")

    if not uuid or not server:
        raise ValueError("vless URL missing uuid/server")

    outbound: dict = {
        "type": "vless",
        "tag": "proxy",
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "network": network,
    }

    flow = first(params, "flow")
    if flow:
        outbound["flow"] = flow

    if network == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": first(params, "path", "/"),
            "headers": {"Host": first(params, "host", server)},
        }
    elif network == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": first(params, "serviceName", first(params, "service_name", "")),
        }

    if security in {"tls", "reality"}:
        tls: dict = {
            "enabled": True,
            "server_name": first(params, "sni", server),
        }

        fingerprint = first(params, "fp")
        if fingerprint:
            tls["utls"] = {
                "enabled": True,
                "fingerprint": fingerprint,
            }

        if security == "reality":
            public_key = first(params, "pbk")
            short_id = first(params, "sid", "")
            if not public_key:
                raise ValueError("reality VLESS missing pbk")
            tls["reality"] = {
                "enabled": True,
                "public_key": public_key,
                "short_id": short_id,
            }

        outbound["tls"] = tls

    return outbound


def build_singbox_config(vless_url: str, listen_port: int) -> dict:
    return {
        "log": {
            "level": "warn",
            "timestamp": True,
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": listen_port,
                "set_system_proxy": False,
            }
        ],
        "outbounds": [
            parse_vless_url(vless_url),
            {
                "type": "direct",
                "tag": "direct",
            },
        ],
        "route": {
            "final": "proxy",
        },
    }


def run_cmd(cmd: list[str], timeout: int = 30, input_text: str | None = None) -> tuple[int, str]:
    proc = subprocess.run(
        cmd,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, (proc.stdout or "").strip()


def stop_process(proc: subprocess.Popen | None):
    if not proc:
        return
    try:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def write_checked_config(vless_url: str, path: Path, port: int):
    path.write_text(json.dumps(build_singbox_config(vless_url, port), ensure_ascii=False, indent=2), encoding="utf-8")
    code, out = run_cmd(["sing-box", "check", "-c", str(path)], timeout=20)
    if code != 0:
        raise RuntimeError("sing-box check failed: " + out[-800:])


def start_singbox(vless_url: str, path: Path, port: int) -> subprocess.Popen:
    write_checked_config(vless_url, path, port)
    proc = subprocess.Popen(
        ["sing-box", "run", "-c", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(SINGBOX_STARTUP_WAIT)
    if proc.poll() is not None:
        logs = ""
        try:
            logs = (proc.stdout.read() if proc.stdout else "")[-800:]
        except Exception:
            pass
        raise RuntimeError("sing-box exited early: " + logs)
    return proc


def curl_text(url: str, proxy_port: int | None, timeout: int = CURL_TIMEOUT, extra_headers: list[str] | None = None, data: str | None = None) -> tuple[int, str]:
    cmd = [
        "curl",
        "-sS",
        "--max-time", str(timeout),
        "--connect-timeout", "8",
    ]
    if proxy_port:
        cmd += ["--proxy", f"socks5h://127.0.0.1:{proxy_port}"]
    for header in extra_headers or []:
        cmd += ["-H", header]
    if data is not None:
        cmd += ["-X", "POST", "--data-binary", data]
    cmd.append(url)
    return run_cmd(cmd, timeout=timeout + 5)


def api_get(path: str) -> dict:
    code, out = curl_text(
        API_BASE + path,
        proxy_port=CONTROL_PORT,
        timeout=30,
        extra_headers=[f"X-Tester-Token: {TOKEN}"],
    )
    if code != 0:
        raise RuntimeError("API GET failed: " + out[-500:])
    return json.loads(out)


def api_post(path: str, payload: dict) -> dict:
    body = json.dumps(payload, ensure_ascii=False)
    code, out = curl_text(
        API_BASE + path,
        proxy_port=CONTROL_PORT,
        timeout=40,
        extra_headers=[f"X-Tester-Token: {TOKEN}", "Content-Type: application/json"],
        data=body,
    )
    if code != 0:
        raise RuntimeError("API POST failed: " + out[-500:])
    return json.loads(out)


def log_tail() -> str:
    return "\n".join(LOG_BUFFER)


def send_heartbeat(control_ok: bool = True, current_task: str = "", last_error: str = ""):
    payload = {
        "worker": WORKER_ID,
        "control_ok": control_ok,
        "api_ok": True,
        "current_task": current_task,
        "last_error": last_error,
        "network": "unknown",
        "battery": "",
        "version": AGENT_VERSION,
        "log_tail": log_tail(),
    }
    api_post("/worker_heartbeat", payload)


def direct_ip() -> tuple[bool, str | None]:
    try:
        code, out = curl_text(DIRECT_TEST_URL, proxy_port=None, timeout=8)
        out = out.strip()
        return code == 0 and bool(out), out or None
    except Exception:
        return False, None


def test_vless(task: dict) -> dict:
    test_id = task["id"]
    expected_ip = task.get("ip") or ""
    vless_url = task["vless_url"]
    proc = None
    started = time.time()
    direct_ok, direct_seen_ip = direct_ip()

    try:
        proc = start_singbox(vless_url, TEST_CONFIG, TEST_PORT)
        code, out = curl_text(TEST_URL, proxy_port=TEST_PORT, timeout=CURL_TIMEOUT)
        latency_ms = int((time.time() - started) * 1000)
        exit_ip = out.strip()

        if code != 0 or not exit_ip:
            return {
                "id": test_id,
                "ok": False,
                "exit_ip": exit_ip or None,
                "direct_ip": direct_seen_ip,
                "direct_ok": direct_ok,
                "latency_ms": latency_ms,
                "error": "curl_through_test_proxy_failed",
            }

        if expected_ip and exit_ip != expected_ip:
            return {
                "id": test_id,
                "ok": False,
                "exit_ip": exit_ip,
                "direct_ip": direct_seen_ip,
                "direct_ok": direct_ok,
                "latency_ms": latency_ms,
                "error": f"exit_ip_mismatch expected={expected_ip} got={exit_ip}",
            }

        return {
            "id": test_id,
            "ok": True,
            "exit_ip": exit_ip,
            "direct_ip": direct_seen_ip,
            "direct_ok": direct_ok,
            "latency_ms": latency_ms,
            "error": None,
        }

    except Exception as e:
        return {
            "id": test_id,
            "ok": False,
            "exit_ip": None,
            "direct_ip": direct_seen_ip,
            "direct_ok": direct_ok,
            "latency_ms": int((time.time() - started) * 1000),
            "error": repr(e)[:1000],
        }
    finally:
        stop_process(proc)


def append_pending_result(result: dict):
    with PENDING_RESULTS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")


def load_pending_results() -> list[dict]:
    if not PENDING_RESULTS.exists():
        return []
    results = []
    for line in PENDING_RESULTS.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            results.append(json.loads(line))
        except Exception:
            pass
    return results


def clear_pending_results():
    if PENDING_RESULTS.exists():
        PENDING_RESULTS.unlink()


def flush_pending_results():
    results = load_pending_results()
    if not results:
        return
    response = api_post("/results", {"worker": WORKER_ID, "results": results})
    if response.get("ok"):
        clear_pending_results()
        log(f"sent pending results: {len(results)}")
    else:
        raise RuntimeError("/results returned not ok: " + repr(response))


def ensure_control(proc: subprocess.Popen | None) -> subprocess.Popen:
    if proc and proc.poll() is None:
        return proc
    stop_process(proc)
    log("starting control sing-box")
    return start_singbox(CONTROL_VLESS, CONTROL_CONFIG, CONTROL_PORT)


def main():
    if not TOKEN:
        raise SystemExit("TESTER_TOKEN is empty")
    if not CONTROL_VLESS:
        raise SystemExit("CONTROL_VLESS is empty")

    WORK_DIR.mkdir(parents=True, exist_ok=True)
    control_proc = None
    last_heartbeat = 0.0
    log(f"worker started: {WORKER_ID}, api={API_BASE}")

    while True:
        try:
            control_proc = ensure_control(control_proc)

            now = time.time()
            if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                try:
                    send_heartbeat(control_ok=True)
                    last_heartbeat = now
                except Exception as e:
                    log("heartbeat failed: " + repr(e))

            flush_pending_results()

            data = api_get(f"/next_tests?worker={WORKER_ID}&limit={BATCH_SIZE}")
            tasks = data.get("tasks") or []
            if not tasks:
                time.sleep(POLL_SLEEP)
                continue

            log(f"received tasks: {len(tasks)}")
            for task in tasks:
                current_task = f"id={task.get('id')} ip={task.get('ip')}"
                try:
                    send_heartbeat(control_ok=True, current_task=current_task)
                except Exception:
                    pass
                log(f"testing id={task.get('id')} ip={task.get('ip')} region={task.get('region')}")
                result = test_vless(task)
                append_pending_result(result)
                log(f"result id={result.get('id')} ok={result.get('ok')} exit_ip={result.get('exit_ip')} error={result.get('error')}")
                try:
                    flush_pending_results()
                    send_heartbeat(control_ok=True, current_task="", last_error=str(result.get("error") or ""))
                except Exception as e:
                    log("cannot send result now: " + repr(e))

        except KeyboardInterrupt:
            log("stopped")
            break
        except Exception as e:
            err = repr(e)
            log("loop error: " + err)
            try:
                send_heartbeat(control_ok=False, last_error=err)
            except Exception:
                pass
            stop_process(control_proc)
            control_proc = None
            time.sleep(POLL_SLEEP)

    stop_process(control_proc)


if __name__ == "__main__":
    main()
