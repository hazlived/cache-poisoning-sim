"""
Upstream Application Server.
Simulates an enterprise web application that renders dynamic web pages
with external static resource imports. Supports both VULNERABLE and HARDENED modes.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import threading
from typing import Optional
from config import SimulationConfig, DEFAULT_CONFIG

logger = logging.getLogger("UpstreamApp")


class UpstreamRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the upstream backend web application."""

    server: "UpstreamServer"

    def log_message(self, format: str, *args) -> None:
        """Suppress default stderr HTTP request logging for clean console output."""
        pass

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        if path == "/health":
            self._handle_health()
        elif path == "/":
            self._handle_portal_page()
        elif path == "/static/app.js":
            self._handle_legitimate_script()
        else:
            self._send_response(404, "text/plain; charset=utf-8", "Not Found")

    def _handle_health(self) -> None:
        payload = json.dumps({"status": "healthy", "service": "upstream_app"}).encode("utf-8")
        self._send_response(200, "application/json", payload)

    def _handle_legitimate_script(self) -> None:
        """Serves the authentic, legitimate frontend application JavaScript."""
        script_content = (
            "/* Enterprise Core Application Runtime (Legitimate) */\n"
            "window.__APP_STATUS__ = 'AUTHENTIC_ORIGIN_VERIFIED';\n"
            "window.__SCRIPT_SOURCE__ = 'LEGITIMATE_UPSTREAM';\n"
            "console.log('[+] Legitimate corporate application bundle initialized.');\n"
        ).encode("utf-8")

        headers = {
            "Content-Type": "application/javascript; charset=utf-8",
            "Cache-Control": "public, max-age=300",
            "X-Content-Type-Options": "nosniff",
        }
        self._send_response(200, "application/javascript; charset=utf-8", script_content, extra_headers=headers)

    def _handle_portal_page(self) -> None:
        """
        Renders the corporate dashboard.
        Vulnerable behavior: Trusts X-Forwarded-Host to dynamically compute resource URLs.
        Hardened behavior: Canonicalizes resource URLs, validates host, and adds Content-Security-Policy.
        """
        mode = self.server.mode
        config = self.server.config
        forwarded_host = self.headers.get("X-Forwarded-Host")
        request_host = self.headers.get("Host", f"{config.HOST}:{config.UPSTREAM_PORT}")

        extra_headers = {
            "Cache-Control": config.CACHE_CONTROL_HEADER,
            "X-Application-Mode": mode,
        }

        if mode == "vulnerable":
            # VULNERABLE BEHAVIOR:
            # Blindly trust X-Forwarded-Host if provided, otherwise fallback to request Host.
            # This allows an unkeyed header to dictate script origin in the generated HTML.
            script_origin = forwarded_host if forwarded_host else request_host

            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecureCorp Corporate Portal</title>
    <!-- Dynamic asset loading derived from request host headers -->
    <script src="http://{script_origin}/static/app.js"></script>
</head>
<body>
    <div id="app">
        <h1>SecureCorp Financial Dashboard</h1>
        <p>Operational Status: Online</p>
        <div id="auth-status">Authenticated User Session: Active</div>
    </div>
</body>
</html>
""".encode("utf-8")

        else:
            # HARDENED BEHAVIOR:
            # 1. Enforce strict canonical asset host, ignoring unvalidated headers.
            # 2. Add Content-Security-Policy restricting script origins.
            # 3. Add Vary header if multi-tenant host variation is ever used.
            script_origin = config.CANONICAL_STATIC_HOST

            extra_headers["Content-Security-Policy"] = (
                f"default-src 'self'; "
                f"script-src 'self' http://{config.CANONICAL_STATIC_HOST}; "
                f"object-src 'none';"
            )
            extra_headers["Vary"] = "X-Forwarded-Host"
            extra_headers["X-Content-Type-Options"] = "nosniff"

            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecureCorp Corporate Portal [Hardened]</title>
    <!-- Hardened canonical asset loading protected by CSP -->
    <script src="http://{script_origin}/static/app.js"></script>
</head>
<body>
    <div id="app">
        <h1>SecureCorp Financial Dashboard [Hardened]</h1>
        <p>Operational Status: Online (Protected by strict host resolution & CSP)</p>
        <div id="auth-status">Authenticated User Session: Active</div>
    </div>
</body>
</html>
""".encode("utf-8")

        self._send_response(200, "text/html; charset=utf-8", html_content, extra_headers=extra_headers)

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


class UpstreamServer(ThreadingHTTPServer):
    """Managed Upstream Application Server."""

    def __init__(self, config: SimulationConfig = DEFAULT_CONFIG, mode: str = "vulnerable"):
        self.config = config
        self.mode = mode
        super().__init__((config.HOST, config.UPSTREAM_PORT), UpstreamRequestHandler)
        self._thread: Optional[threading.Thread] = None

    def start_background(self) -> None:
        """Starts the upstream server in a dedicated daemon thread."""
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Shuts down the server and cleans up resources."""
        self.shutdown()
        self.server_close()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

