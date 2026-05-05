import base64
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def make_tester_api_handler(ctx):
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

        def _send_bytes(self, status: int, data: bytes, content_type: str):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _send_dashboard_app(self):
            try:
                data, content_type = ctx.dashboard_static_content("index.html")
                self._send_bytes(200, data, content_type)
            except FileNotFoundError:
                self._send_text(503, "dashboard/index.html not found")

        def _send_download(self, filename: str, text: str):
            data = text.encode("utf-8")
            safe_name = ctx.normalize_managed_list_name(filename)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
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
            if not ctx.TESTER_TOKEN:
                return False
            return hmac.compare_digest(self.headers.get("X-Tester-Token", ""), ctx.TESTER_TOKEN)

        def _dashboard_authorized(self) -> bool:
            if not ctx.DASHBOARD_ENABLED or not ctx.DASHBOARD_PASSWORD:
                return False
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Basic "):
                return False
            try:
                decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
                username, password = decoded.split(":", 1)
            except Exception:
                return False
            return hmac.compare_digest(username, ctx.DASHBOARD_USERNAME) and hmac.compare_digest(password, ctx.DASHBOARD_PASSWORD)

        def _require_dashboard_auth(self) -> bool:
            if not ctx.DASHBOARD_ENABLED:
                self._send_text(404, "dashboard disabled")
                return False
            if not ctx.DASHBOARD_PASSWORD:
                self._send_text(503, "DASHBOARD_PASSWORD is empty")
                return False
            if not self._dashboard_authorized():
                self._send_dashboard_login()
                return False
            return True

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/health":
                self._send_json(200, {"ok": True, **ctx.get_tester_control_state(), "stats": ctx.get_vless_queue_stats()})
                return

            if parsed.path in {"/dashboard", "/dashboard/", "/dashboard/index.html", "/dashboard/settings"}:
                if not self._require_dashboard_auth():
                    return
                self._send_dashboard_app()
                return

            if parsed.path.startswith("/dashboard/assets/"):
                if not self._require_dashboard_auth():
                    return
                try:
                    relative_path = parsed.path.removeprefix("/dashboard/")
                    data, content_type = ctx.dashboard_static_content(relative_path)
                    self._send_bytes(200, data, content_type)
                except FileNotFoundError:
                    self._send_text(404, "dashboard asset not found")
                except Exception as e:
                    self._send_text(400, str(e))
                return

            if parsed.path == "/dashboard/api/status":
                if not self._require_dashboard_auth():
                    return
                self._send_json(200, ctx.dashboard_snapshot())
                return

            if parsed.path == "/dashboard/api/settings":
                if not self._require_dashboard_auth():
                    return
                self._send_json(200, ctx.dashboard_settings_snapshot())
                return

            if parsed.path == "/dashboard/api/list":
                if not self._require_dashboard_auth():
                    return
                try:
                    query = parse_qs(parsed.query)
                    name = (query.get("name") or [""])[0]
                    if name:
                        self._send_json(200, ctx.read_managed_list(name))
                    else:
                        self._send_json(200, {"ok": True, "lists": ctx.managed_lists_snapshot()})
                except Exception as e:
                    self._send_json(400, {"ok": False, "error": str(e)})
                return

            if parsed.path == "/dashboard/api/list_download":
                if not self._require_dashboard_auth():
                    return
                try:
                    query = parse_qs(parsed.query)
                    name = (query.get("name") or [""])[0]
                    item = ctx.read_managed_list(name)
                    self._send_download(item["name"], item["content"])
                except Exception as e:
                    self._send_json(400, {"ok": False, "error": str(e)})
                return

            if parsed.path == "/dashboard/api/logs":
                if not self._require_dashboard_auth():
                    return
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "finder_log": ctx.tail_file_text(ctx.LOG_FILE, ctx.DASHBOARD_LOG_LINES),
                        "workers": ctx.get_worker_statuses(),
                    },
                )
                return

            if not self._authorized():
                self._send_json(401, {"ok": False, "error": "unauthorized"})
                return

            if parsed.path == "/next_tests":
                query = parse_qs(parsed.query)
                worker = (query.get("worker") or ["unknown-worker"])[0]
                limit_raw = (query.get("limit") or [str(ctx.tester_batch_size())])[0]
                try:
                    limit = int(limit_raw)
                except ValueError:
                    limit = ctx.tester_batch_size()
                if ctx.is_testing_paused():
                    self._send_json(200, {"ok": True, "paused": True, "tasks": []})
                    return
                tasks = ctx.reserve_vless_tests(worker=worker, limit=limit)
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
                        self._send_json(200, ctx.apply_runtime_preset(preset, actor=ctx.DASHBOARD_USERNAME))
                    else:
                        self._send_json(200, ctx.update_runtime_settings(payload, actor=ctx.DASHBOARD_USERNAME))
                except Exception as e:
                    print(f"[dashboard] settings error: {e}", flush=True)
                    self._send_json(400, {"ok": False, "error": str(e)})
                return

            if parsed.path == "/dashboard/api/list":
                if not self._require_dashboard_auth():
                    return
                try:
                    payload = self._read_json()
                    name = payload.get("name") or ""
                    content = payload.get("content") or ""
                    self._send_json(200, ctx.save_managed_list(name, content, actor=ctx.DASHBOARD_USERNAME))
                except Exception as e:
                    print(f"[dashboard] list save error: {e}", flush=True)
                    self._send_json(400, {"ok": False, "error": str(e)})
                return

            if parsed.path == "/dashboard/api/bulk_action":
                if not self._require_dashboard_auth():
                    return
                try:
                    payload = self._read_json()
                    result = ctx.bulk_dashboard_action(payload, actor=ctx.DASHBOARD_USERNAME)
                    result["stats"] = ctx.get_vless_queue_stats()
                    self._send_json(200, result)
                except Exception as e:
                    print(f"[dashboard] bulk action error: {e}", flush=True)
                    self._send_json(400, {"ok": False, "error": str(e)})
                return

            if parsed.path == "/dashboard/api/finder_control":
                if not self._require_dashboard_auth():
                    return
                try:
                    payload = self._read_json()
                    action = (payload.get("action") or "").strip().lower()
                    if action == "start":
                        result = ctx.start_finder(actor=ctx.DASHBOARD_USERNAME)
                    elif action == "stop":
                        result = ctx.stop_finder(actor=ctx.DASHBOARD_USERNAME)
                    elif action == "auto_on":
                        result = ctx.enable_full_auto_mode(actor=ctx.DASHBOARD_USERNAME)
                    elif action == "auto_off":
                        result = ctx.disable_full_auto_mode(actor=ctx.DASHBOARD_USERNAME)
                    elif action == "auto_toggle":
                        result = (
                            ctx.disable_full_auto_mode(actor=ctx.DASHBOARD_USERNAME)
                            if ctx.is_full_auto_mode_enabled()
                            else ctx.enable_full_auto_mode(actor=ctx.DASHBOARD_USERNAME)
                        )
                    else:
                        raise RuntimeError("unknown finder action")
                    self._send_json(200, {"ok": True, "result": result, "snapshot": ctx.dashboard_snapshot()})
                except Exception as e:
                    print(f"[dashboard] finder control error: {e}", flush=True)
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
                        result = ctx.start_manual_retry(test_id, actor=ctx.DASHBOARD_USERNAME)
                    elif action == "delete":
                        result = ctx.manually_delete_vless_test(test_id, actor=ctx.DASHBOARD_USERNAME)
                    else:
                        raise RuntimeError("unknown action")
                    self._send_json(200, {"ok": True, "result": result, "stats": ctx.get_vless_queue_stats()})
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
                    saved = ctx.save_worker_heartbeat(payload, worker=worker)
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
                saved = [ctx.complete_vless_test_result(item, worker=worker) for item in results]
                ctx.save_worker_heartbeat(
                    {"worker": worker, "api_ok": True, "control_ok": True, "current_task": "", "last_error": "", "log_tail": ""},
                    worker=worker,
                )
                auto = ctx.auto_mode_tick(reason="tester_results")
                self._send_json(200, {"ok": True, "saved": saved, "stats": ctx.get_vless_queue_stats(), "auto": auto})
            except Exception as e:
                print(f"[tester-api] POST /results error: {e}", flush=True)
                self._send_json(400, {"ok": False, "error": str(e)})

    return TesterAPIHandler


def start_tester_api_if_enabled(ctx):
    ctx.init_vless_queue()

    if not ctx.TESTER_API_ENABLED:
        print("[tester-api] disabled: TESTER_API_ENABLED=false", flush=True)
        return None
    if not ctx.TESTER_TOKEN:
        print("[tester-api] disabled: TESTER_TOKEN is empty", flush=True)
        ctx.send(ctx.TELEGRAM_ALLOWED_CHAT_ID, "⚠️ API авто-тестера выключен: TESTER_TOKEN пустой")
        return None

    try:
        handler = make_tester_api_handler(ctx)
        server = ThreadingHTTPServer((ctx.TESTER_API_HOST, ctx.TESTER_API_PORT), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        print(f"[tester-api] listening on {ctx.TESTER_API_HOST}:{ctx.TESTER_API_PORT}", flush=True)
        if ctx.DASHBOARD_ENABLED:
            print(f"[dashboard] enabled on /dashboard user={ctx.DASHBOARD_USERNAME}", flush=True)
        ctx.send(ctx.TELEGRAM_ALLOWED_CHAT_ID, f"📲 API авто-тестера запущен: {ctx.TESTER_API_HOST}:{ctx.TESTER_API_PORT}")
        return server
    except Exception as e:
        print(f"[tester-api] failed to start: {e}", flush=True)
        ctx.send(ctx.TELEGRAM_ALLOWED_CHAT_ID, f"⚠️ API авто-тестера не запустился: {e}")
        return None
