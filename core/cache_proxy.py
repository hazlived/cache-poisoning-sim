"""
Caching Reverse Proxy Server.
Simulates an edge CDN / caching reverse proxy (e.g., Cloudflare, CloudFront, Varnish, Nginx).
Demonstrates cache key generation, cache hits, misses, TTL expiration, unkeyed header forwarding,
and edge-layer defense mechanisms (header stripping, Vary evaluation, key normalization).
"""

from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import logging
import threading
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from config import SimulationConfig, DEFAULT_CONFIG

logger = logging.getLogger("CacheProxy")


@dataclass
class CacheEntry:
    """Represents a cached HTTP response in memory."""

    cache_key: str
    status_code: int
    headers: List[Tuple[str, str]]
    body: bytes
    created_at: float
    ttl: int

    @property
    def age(self) -> int:
        return int(time.time() - self.created_at)

    @property
    def is_expired(self) -> bool:
        return self.age >= self.ttl


class CacheStore:
    """Thread-safe in-memory cache store with TTL expiration."""

    def __init__(self):
        self._entries: Dict[str, CacheEntry] = {}
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[CacheEntry]:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self.misses += 1
                return None
            if entry.is_expired:
                del self._entries[key]
                self.misses += 1
                return None
            self.hits += 1
            return entry

    def set(self, key: str, status_code: int, headers: List[Tuple[str, str]], body: bytes, ttl: int) -> CacheEntry:
        with self._lock:
            entry = CacheEntry(
                cache_key=key,
                status_code=status_code,
                headers=headers,
                body=body,
                created_at=time.time(),
                ttl=ttl,
            )
            self._entries[key] = entry
            return entry

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self.hits = 0
            self.misses = 0

    def stats(self) -> dict:
        with self._lock:
            return {
                "active_entries": len(self._entries),
                "hits": self.hits,
                "misses": self.misses,
                "keys": list(self._entries.keys()),
            }


class CacheProxyRequestHandler(BaseHTTPRequestHandler):
    """Handles incoming requests, evaluates cache keys, and proxies upstream."""

    server: "ProxyCacheServer"

    def log_message(self, format: str, *args) -> None:
        """Suppress default stderr HTTP request logging for clean console output."""
        pass

    def do_GET(self) -> None:
        path = self.path

        # Internal administrative endpoints
        if path == "/cache/status":
            self._handle_status()
            return
        elif path == "/cache/purge":
            self._handle_purge()
            return

        # 1. Compute Cache Key
        cache_key = self._compute_cache_key()

        # 2. Check Cache
        cached_entry = self.server.cache_store.get(cache_key)
        if cached_entry:
            self._serve_cached_response(cached_entry)
            return

        # 3. Cache Miss: Forward request to Upstream
        self._forward_to_upstream(cache_key)

    def _compute_cache_key(self) -> str:
        """
        Computes the cache key for the incoming request.
        VULNERABLE (Default) Key: METHOD + HOST + PATH
        Notice that unkeyed headers (like X-Forwarded-Host) are excluded from the key.
        HARDENED Mode:
        If configured, honors Vary headers or explicitly incorporates selected unkeyed headers.
        """
        method = self.command.upper()
        host = self.headers.get("Host", f"{self.server.config.HOST}:{self.server.config.CACHE_PROXY_PORT}")
        path = self.path

        key_components = [method, host, path]

        if self.server.harden_keys:
            # When key hardening is active, include X-Forwarded-Host in the cache key
            fwd_host = self.headers.get("X-Forwarded-Host", "")
            if fwd_host:
                key_components.append(f"XFH:{fwd_host}")

        return ":".join(key_components)

    def _forward_to_upstream(self, cache_key: str) -> None:
        """Proxies the request upstream, handles caching if eligible, and returns response."""
        upstream_host = self.server.config.HOST
        upstream_port = self.server.config.UPSTREAM_PORT

        try:
            conn = http.client.HTTPConnection(upstream_host, upstream_port, timeout=5)

            # Prepare forwarded headers
            forward_headers = {}
            for header_name, header_val in self.headers.items():
                # In hardened mode with edge stripping, drop dangerous unkeyed headers from clients
                if self.server.strip_unkeyed_headers and header_name.lower() in [
                    "x-forwarded-host",
                    "x-forwarded-scheme",
                    "x-original-url",
                    "x-rewrite-url",
                ]:
                    continue
                forward_headers[header_name] = header_val

            # Execute upstream request
            conn.request(self.command, self.path, headers=forward_headers)
            upstream_resp = conn.getresponse()
            status = upstream_resp.status
            body = upstream_resp.read()

            resp_headers: List[Tuple[str, str]] = []
            cache_control_val = ""
            vary_val = ""

            for h_k, h_v in upstream_resp.getheaders():
                # Filter out hop-by-hop headers
                if h_k.lower() in ["connection", "transfer-encoding", "keep-alive"]:
                    continue
                if h_k.lower() == "cache-control":
                    cache_control_val = h_v
                if h_k.lower() == "vary":
                    vary_val = h_v
                resp_headers.append((h_k, h_v))

            conn.close()

            # Determine cacheability: Status 200 and 'public' cache-control
            is_cacheable = status == 200 and "public" in cache_control_val.lower()

            if is_cacheable:
                ttl = self.server.config.DEFAULT_CACHE_TTL
                if "max-age=" in cache_control_val:
                    try:
                        ttl = int(cache_control_val.split("max-age=")[1].split(",")[0].strip())
                    except Exception:
                        ttl = self.server.config.DEFAULT_CACHE_TTL

                self.server.cache_store.set(cache_key, status, resp_headers, body, ttl)

            # Send response back to client with diagnostic cache headers
            self.send_response(status)
            for k, v in resp_headers:
                self.send_header(k, v)

            self.send_header("X-Cache", "MISS")
            self.send_header("X-Cache-Key", cache_key)
            self.send_header("Age", "0")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        except Exception as e:
            err_body = f"Upstream Gateway Error: {str(e)}".encode("utf-8")
            self.send_response(502)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(err_body)))
            self.end_headers()
            self.wfile.write(err_body)

    def _serve_cached_response(self, entry: CacheEntry) -> None:
        """Returns the pre-cached response from the edge store."""
        self.send_response(entry.status_code)
        for k, v in entry.headers:
            if k.lower() not in ["x-cache", "x-cache-key", "age", "content-length"]:
                self.send_header(k, v)

        self.send_header("X-Cache", "HIT")
        self.send_header("X-Cache-Key", entry.cache_key)
        self.send_header("Age", str(entry.age))
        self.send_header("Content-Length", str(len(entry.body)))
        self.end_headers()
        self.wfile.write(entry.body)

    def _handle_status(self) -> None:
        stats = self.server.cache_store.stats()
        body = json.dumps(stats, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_purge(self) -> None:
        self.server.cache_store.clear()
        body = json.dumps({"status": "cache_purged"}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ProxyCacheServer(ThreadingHTTPServer):
    """Managed Reverse Proxy Cache Server."""

    def __init__(
        self,
        config: SimulationConfig = DEFAULT_CONFIG,
        strip_unkeyed_headers: bool = False,
        harden_keys: bool = False,
    ):
        self.config = config
        self.cache_store = CacheStore()
        self.strip_unkeyed_headers = strip_unkeyed_headers
        self.harden_keys = harden_keys
        super().__init__((config.HOST, config.CACHE_PROXY_PORT), CacheProxyRequestHandler)
        self._thread: Optional[threading.Thread] = None

    def start_background(self) -> None:
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

