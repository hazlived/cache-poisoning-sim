"""
Mock Attacker Origin Server.
Simulates an external, attacker-controlled origin serving a verification canary script.
Tracks access metrics so that tests and simulation runs can programmatically confirm
when an innocent user or automated browser fetched resources from the hostile origin.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import threading
from typing import List, Optional
from config import SimulationConfig, DEFAULT_CONFIG

logger = logging.getLogger("MockAttackerOrigin")


class MockAttackerRequestHandler(BaseHTTPRequestHandler):
    """Handler for the attacker's mock CDN/asset hosting server."""

    server: "MockAttackerServer"

    def log_message(self, format: str, *args) -> None:
        """Suppress default stderr HTTP request logging for clean console output."""
        pass

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        client_ip = self.client_address[0]
        user_agent = self.headers.get("User-Agent", "Unknown")

        # Record incoming request in server audit log
        self.server.record_hit(path, client_ip, user_agent)

        if path == "/health":
            self._handle_health()
        elif path == "/static/app.js":
            self._handle_canary_payload()
        elif path == "/stats":
            self._handle_stats()
        else:
            self._send_response(404, "text/plain; charset=utf-8", b"Not Found")

    def _handle_health(self) -> None:
        payload = json.dumps({"status": "active", "service": "mock_attacker_origin"}).encode("utf-8")
        self._send_response(200, "application/json", payload)

    def _handle_stats(self) -> None:
        stats = {
            "total_hits": len(self.server.access_logs),
            "logs": self.server.access_logs,
        }
        self._send_response(200, "application/json", json.dumps(stats).encode("utf-8"))

    def _handle_canary_payload(self) -> None:
        """
        Serves the benign verification canary script.
        Demonstrates that client-side script execution would occur in the victim's browser
        origin, without delivering harmful or destructive payloads.
        """
        canary_script = (
            "/* ========================================================== */\n"
            "/* [!] PROOF-OF-CONCEPT CANARY: UNKEYED CACHE POISONING      */\n"
            "/* ========================================================== */\n"
            "window.__POISONED_CANARY__ = true;\n"
            "window.__EXPLOIT_ORIGIN__ = 'http://127.0.0.1:8882';\n"
            "window.__EXECUTION_TIMESTAMP__ = new Date().toISOString();\n"
            "console.error('[!] HIGH SEVERITY ALERT: External script executed from attacker origin!');\n"
            "if (typeof document !== 'undefined') {\n"
            "    const banner = document.createElement('div');\n"
            "    banner.id = 'cache-poison-alert';\n"
            "    banner.style.cssText = 'background: #dc2626; color: white; padding: 12px; font-weight: bold; text-align: center;';\n"
            "    banner.textContent = 'CRITICAL ALERT: Page rendered using poisoned cache resource from http://127.0.0.1:8882';\n"
            "    document.body?.prepend(banner);\n"
            "}\n"
        ).encode("utf-8")

        headers = {
            "Content-Type": "application/javascript; charset=utf-8",
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "no-store",
        }
        self._send_response(200, "application/javascript; charset=utf-8", canary_script, extra_headers=headers)

    def _send_response(
        self,
        status_code: int,
        content_type: str,
        body: bytes,
        extra_headers: Optional[dict] = None,
    ) -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


class MockAttackerServer(ThreadingHTTPServer):
    """Managed Mock Attacker Origin Server."""

    def __init__(self, config: SimulationConfig = DEFAULT_CONFIG):
        self.config = config
        self.access_logs: List[dict] = []
        self._lock = threading.Lock()
        super().__init__((config.HOST, config.ATTACKER_ORIGIN_PORT), MockAttackerRequestHandler)
        self._thread: Optional[threading.Thread] = None

    def record_hit(self, path: str, ip: str, ua: str) -> None:
        with self._lock:
            self.access_logs.append({
                "path": path,
                "ip": ip,
                "user_agent": ua,
            })

    def clear_logs(self) -> None:
        with self._lock:
            self.access_logs.clear()

    def start_background(self) -> None:
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

