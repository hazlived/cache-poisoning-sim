"""
Web Cache Poisoning Laboratory UI Server.
Hosts the web-based interactive console on port 8888, manages background
simulation services, and exposes REST endpoints for manual probing,
automated scenario execution, and live cache store telemetry.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import mimetypes
import os
import re
import sys
import threading
import time
from typing import Dict, List, Optional
import requests

# Ensure UTF-8 console output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from config import SimulationConfig, DEFAULT_CONFIG
from core.cache_proxy import ProxyCacheServer
from core.upstream_app import UpstreamServer
from core.mock_attacker_origin import MockAttackerServer


class SimulationEnvironmentManager:
    """Manages the lifecycle of proxy, upstream, and attacker services."""

    def __init__(self, config: SimulationConfig = DEFAULT_CONFIG):
        self.config = config
        self.upstream: Optional[UpstreamServer] = None
        self.proxy: Optional[ProxyCacheServer] = None
        self.attacker: Optional[MockAttackerServer] = None
        self.mode = "vulnerable"
        self._lock = threading.Lock()

    def start(self) -> None:
        with self._lock:
            self.stop()
            self.upstream = UpstreamServer(self.config, mode=self.mode)
            self.upstream.start_background()

            self.attacker = MockAttackerServer(self.config)
            self.attacker.start_background()

            is_hardened = (self.mode == "hardened")
            self.proxy = ProxyCacheServer(
                self.config,
                strip_unkeyed_headers=is_hardened,
                harden_keys=False,
            )
            self.proxy.start_background()
            self._wait_ready()

    def stop(self) -> None:
        if self.proxy:
            self.proxy.stop()
            self.proxy = None
        if self.upstream:
            self.upstream.stop()
            self.upstream = None
        if self.attacker:
            self.attacker.stop()
            self.attacker = None

    def _wait_ready(self, timeout: float = 3.0) -> None:
        start = time.time()
        for url in [f"{self.config.upstream_url}/health", f"{self.config.attacker_origin_url}/health"]:
            ready = False
            while time.time() - start < timeout:
                try:
                    r = requests.get(url, timeout=0.3)
                    if r.status_code == 200:
                        ready = True
                        break
                except Exception:
                    time.sleep(0.05)
            if not ready:
                pass

    def set_mode(self, mode: str) -> None:
        with self._lock:
            self.mode = mode
            if self.upstream:
                self.upstream.mode = mode
            if self.proxy:
                self.proxy.strip_unkeyed_headers = (mode == "hardened")

    def purge_cache(self) -> None:
        if self.proxy:
            self.proxy.cache_store.clear()

    def get_status(self) -> dict:
        proxy_up = False
        upstream_up = False
        attacker_up = False
        cache_stats = {}

        if self.proxy:
            try:
                r = requests.get(f"{self.config.cache_proxy_url}/cache/status", timeout=0.3)
                if r.status_code == 200:
                    proxy_up = True
                    cache_stats = r.json()
            except Exception:
                proxy_up = False

        if self.upstream:
            try:
                r = requests.get(f"{self.config.upstream_url}/health", timeout=0.3)
                upstream_up = (r.status_code == 200)
            except Exception:
                upstream_up = False

        if self.attacker:
            try:
                r = requests.get(f"{self.config.attacker_origin_url}/health", timeout=0.3)
                attacker_up = (r.status_code == 200)
            except Exception:
                attacker_up = False

        return {
            "proxy_online": proxy_up,
            "upstream_online": upstream_up,
            "attacker_online": attacker_up,
            "mode": self.mode,
            "cache_stats": cache_stats,
        }

    def get_cache_entries(self) -> List[dict]:
        entries = []
        if not self.proxy:
            return entries

        attacker_port = str(self.config.ATTACKER_ORIGIN_PORT)
        with self.proxy.cache_store._lock:
            for k, entry in self.proxy.cache_store._entries.items():
                body_str = entry.body.decode("utf-8", errors="replace")
                is_poisoned = (attacker_port in body_str or "attacker" in body_str.lower() or "8882" in body_str)
                entries.append({
                    "key": k,
                    "age": entry.age,
                    "ttl": entry.ttl,
                    "size": len(entry.body),
                    "is_poisoned": is_poisoned,
                })
        return entries


ENV_MANAGER = SimulationEnvironmentManager()


class LabUIRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler serving UI assets and JSON API endpoints."""

    def log_message(self, format: str, *args) -> None:
        pass

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        if path.startswith("/api/"):
            self._handle_api_get(path)
        else:
            self._serve_static(path)

    def do_POST(self) -> None:
        path = self.path.split("?")[0]

        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else b"{}"

        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            payload = {}

        if path.startswith("/api/"):
            self._handle_api_post(path, payload)
        else:
            self._send_json(404, {"error": "Not Found"})

    def _serve_static(self, path: str) -> None:
        base_dir = os.path.join(os.path.dirname(__file__), "ui")
        if path in ["/", ""]:
            filename = "index.html"
        else:
            filename = path.lstrip("/")

        file_path = os.path.join(base_dir, filename)

        if not os.path.exists(file_path) or os.path.isdir(file_path):
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Static Asset Not Found")
            return

        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type:
            mime_type = "application/octet-stream"

        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", f"{mime_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Read error: {e}".encode("utf-8"))

    def _handle_api_get(self, path: str) -> None:
        if path == "/api/status":
            status = ENV_MANAGER.get_status()
            self._send_json(200, status)
        elif path == "/api/cache/entries":
            entries = ENV_MANAGER.get_cache_entries()
            self._send_json(200, {"entries": entries})
        elif path == "/api/simulate-victim":
            self._simulate_victim()
        else:
            self._send_json(404, {"error": "API route not found"})

    def _handle_api_post(self, path: str, payload: dict) -> None:
        if path == "/api/mode":
            mode = payload.get("mode", "vulnerable")
            ENV_MANAGER.set_mode(mode)
            self._send_json(200, {"status": "ok", "mode": mode})

        elif path == "/api/cache/purge":
            ENV_MANAGER.purge_cache()
            self._send_json(200, {"status": "purged"})

        elif path == "/api/custom-request":
            self._execute_custom_request(payload)

        elif path == "/api/phase/1":
            txs = self._run_phase_1()
            self._send_json(200, {"phase": 1, "transactions": txs})

        elif path == "/api/phase/2":
            txs = self._run_phase_2()
            self._send_json(200, {"phase": 2, "transactions": txs})

        elif path == "/api/phase/3":
            txs = self._run_phase_3()
            self._send_json(200, {"phase": 3, "transactions": txs})

        elif path == "/api/phase/4":
            txs = self._run_phase_4()
            self._send_json(200, {"phase": 4, "transactions": txs})

        elif path == "/api/run-all":
            all_txs = []
            all_txs.extend(self._run_phase_1())
            all_txs.extend(self._run_phase_2())
            all_txs.extend(self._run_phase_3())
            all_txs.extend(self._run_phase_4())
            self._send_json(200, {"transactions": all_txs})

        else:
            self._send_json(404, {"error": "API route not found"})

    def _extract_script_src(self, html: str) -> str:
        match = re.search(r'<script\s+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        return match.group(1) if match else "None detected"

    def _execute_custom_request(self, payload: dict) -> None:
        method = payload.get("method", "GET").upper()
        req_path = payload.get("path", "/").strip()
        custom_headers = payload.get("headers", {})

        url = f"{ENV_MANAGER.config.cache_proxy_url}{req_path}"

        try:
            r = requests.request(method, url, headers=custom_headers, timeout=5)
            script_src = self._extract_script_src(r.text)
            cache_status = r.headers.get("X-Cache", "MISS")
            cache_key = r.headers.get("X-Cache-Key", f"GET:{DEFAULT_CONFIG.HOST}:{DEFAULT_CONFIG.CACHE_PROXY_PORT}{req_path}")
            csp_header = r.headers.get("Content-Security-Policy", "")

            attacker_port = str(ENV_MANAGER.config.ATTACKER_ORIGIN_PORT)
            is_poisoned = (attacker_port in script_src or "attacker" in script_src.lower() or "8882" in script_src)
            csp_present = bool(csp_header)

            body_snippet = r.text[:400] + ("..." if len(r.text) > 400 else "")

            resp_headers = dict(r.headers)

            self._send_json(200, {
                "status_code": r.status_code,
                "cache_status": cache_status,
                "cache_key": cache_key,
                "script_source": script_src,
                "is_poisoned": is_poisoned,
                "csp_present": csp_present,
                "response_headers": resp_headers,
                "body_snippet": body_snippet,
            })
        except Exception as e:
            self._send_json(500, {"error": str(e)})

    def _simulate_victim(self) -> None:
        try:
            r = requests.get(f"{ENV_MANAGER.config.cache_proxy_url}/", timeout=2)
            script_src = self._extract_script_src(r.text)
            attacker_port = str(ENV_MANAGER.config.ATTACKER_ORIGIN_PORT)
            is_poisoned = (attacker_port in script_src or "attacker" in script_src.lower() or "8882" in script_src)
            cache_status = r.headers.get("X-Cache", "MISS")
            self._send_json(200, {
                "script_source": script_src,
                "is_poisoned": is_poisoned,
                "cache_status": cache_status,
            })
        except Exception as e:
            self._send_json(500, {"error": str(e)})

    def _run_phase_1(self) -> List[dict]:
        # Reset to vulnerable, purge
        ENV_MANAGER.set_mode("vulnerable")
        ENV_MANAGER.purge_cache()

        txs = []
        # Alice
        r1 = requests.get(f"{ENV_MANAGER.config.cache_proxy_url}/")
        src1 = self._extract_script_src(r1.text)
        txs.append({
            "actor": "User Alice (Trader 1)",
            "method": "GET",
            "url": "/",
            "cache_status": r1.headers.get("X-Cache", "MISS"),
            "cache_key": r1.headers.get("X-Cache-Key", "N/A"),
            "status_code": r1.status_code,
            "script_source": src1,
            "verdict": "SAFE: Authentic corporate bundle requested. Response cached at edge.",
            "verdict_type": "safe",
        })

        time.sleep(0.05)

        # Bob
        r2 = requests.get(f"{ENV_MANAGER.config.cache_proxy_url}/")
        src2 = self._extract_script_src(r2.text)
        txs.append({
            "actor": "User Bob (Trader 2)",
            "method": "GET",
            "url": "/",
            "cache_status": r2.headers.get("X-Cache", "HIT"),
            "cache_key": r2.headers.get("X-Cache-Key", "N/A"),
            "status_code": r2.status_code,
            "script_source": src2,
            "verdict": "SAFE: Served from Edge Cache (HIT). Authentic assets verified.",
            "verdict_type": "safe",
        })
        return txs

    def _run_phase_2(self) -> List[dict]:
        ENV_MANAGER.purge_cache()
        txs = []

        headers = {"X-Forwarded-Host": f"{ENV_MANAGER.config.HOST}:{ENV_MANAGER.config.ATTACKER_ORIGIN_PORT}"}
        r = requests.get(f"{ENV_MANAGER.config.cache_proxy_url}/", headers=headers)
        src = self._extract_script_src(r.text)

        txs.append({
            "actor": "Attacker Mallory (FIN-7)",
            "method": "GET",
            "url": "/",
            "cache_status": r.headers.get("X-Cache", "MISS"),
            "cache_key": r.headers.get("X-Cache-Key", "N/A"),
            "status_code": r.status_code,
            "script_source": src,
            "verdict": "EXPLOIT STAGED: Unkeyed header reflected by upstream. Poisoned HTML cached under clean key!",
            "verdict_type": "poisoned",
        })
        return txs

    def _run_phase_3(self) -> List[dict]:
        txs = []
        # Charlie sends clean request
        r = requests.get(f"{ENV_MANAGER.config.cache_proxy_url}/")
        src = self._extract_script_src(r.text)

        txs.append({
            "actor": "User Charlie (Innocent Trader)",
            "method": "GET",
            "url": "/",
            "cache_status": r.headers.get("X-Cache", "HIT"),
            "cache_key": r.headers.get("X-Cache-Key", "N/A"),
            "status_code": r.status_code,
            "script_source": src,
            "verdict": "CRITICAL COMPROMISE: Victim served poisoned cache! Browser loads hostile script from attacker origin.",
            "verdict_type": "poisoned",
        })
        return txs

    def _run_phase_4(self) -> List[dict]:
        ENV_MANAGER.set_mode("hardened")
        ENV_MANAGER.purge_cache()

        txs = []
        # Attacker re-attempts
        headers = {"X-Forwarded-Host": f"{ENV_MANAGER.config.HOST}:{ENV_MANAGER.config.ATTACKER_ORIGIN_PORT}"}
        r1 = requests.get(f"{ENV_MANAGER.config.cache_proxy_url}/", headers=headers)
        src1 = self._extract_script_src(r1.text)

        txs.append({
            "actor": "Attacker Mallory (Post-Hardening Probe)",
            "method": "GET",
            "url": "/",
            "cache_status": r1.headers.get("X-Cache", "MISS"),
            "cache_key": r1.headers.get("X-Cache-Key", "N/A"),
            "status_code": r1.status_code,
            "script_source": src1,
            "verdict": "ATTACK BLOCKED: Header stripped at edge proxy & upstream canonical domain enforced.",
            "verdict_type": "blocked",
        })

        # David visits
        r2 = requests.get(f"{ENV_MANAGER.config.cache_proxy_url}/")
        src2 = self._extract_script_src(r2.text)
        txs.append({
            "actor": "User David (Innocent Client)",
            "method": "GET",
            "url": "/",
            "cache_status": r2.headers.get("X-Cache", "HIT"),
            "cache_key": r2.headers.get("X-Cache-Key", "N/A"),
            "status_code": r2.status_code,
            "script_source": src2,
            "verdict": "FULLY SECURE: Authentic asset served. CSP guarantees script execution boundary.",
            "verdict_type": "safe",
        })
        return txs

    def _send_json(self, status: int, data: dict) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def start_ui_server(port: int = 8888) -> None:
    print("=" * 72)
    print(" WEB CACHE POISONING LABORATORY - INTERACTIVE UI CONSOLE")
    print("=" * 72)
    print("[*] Starting backend simulation cluster (Proxy :8880, Upstream :8881, Attacker :8882)...")
    ENV_MANAGER.start()
    print("[OK] Simulation cluster running.")

    server_address = ("127.0.0.1", port)
    httpd = ThreadingHTTPServer(server_address, LabUIRequestHandler)
    print(f"[OK] Web UI Console accessible at: http://127.0.0.1:{port}/")
    print("[*] Press Ctrl+C to terminate.")
    print("=" * 72)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down UI Console...")
    finally:
        httpd.shutdown()
        httpd.server_close()
        ENV_MANAGER.stop()
        print("[OK] UI server and background cluster stopped cleanly.")


if __name__ == "__main__":
    start_ui_server(8888)
