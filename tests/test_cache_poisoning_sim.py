"""
Unit and Integration Tests for Web Cache Poisoning Simulation.
Verifies all stages of vulnerable cache pollution, victim impact,
and edge/upstream hardening mechanisms.
"""

import pytest
import requests
import time
from config import SimulationConfig
from sim.scenarios import SimulationScenarioRunner


@pytest.fixture(scope="module")
def sim_config():
    return SimulationConfig(
        CACHE_PROXY_PORT=8980,
        UPSTREAM_PORT=8981,
        ATTACKER_ORIGIN_PORT=8982,
        DEFAULT_CACHE_TTL=5,
    )


@pytest.fixture
def runner(sim_config):
    runner_instance = SimulationScenarioRunner(sim_config)
    yield runner_instance
    runner_instance.stop_servers()


def test_baseline_caching_behavior(runner, sim_config):
    """Verifies standard cache MISS on first request and HIT on subsequent request."""
    runner.start_servers(upstream_mode="vulnerable", proxy_strip_headers=False)

    # 1. First request -> MISS
    resp1 = requests.get(f"{sim_config.cache_proxy_url}/")
    assert resp1.status_code == 200
    assert resp1.headers.get("X-Cache") == "MISS"
    assert "127.0.0.1:8981" in runner.extract_script_src(resp1.text) or "127.0.0.1:8980" in runner.extract_script_src(resp1.text)

    # 2. Second request -> HIT
    resp2 = requests.get(f"{sim_config.cache_proxy_url}/")
    assert resp2.status_code == 200
    assert resp2.headers.get("X-Cache") == "HIT"
    assert resp2.text == resp1.text


def test_unkeyed_header_cache_poisoning(runner, sim_config):
    """
    Verifies that unkeyed X-Forwarded-Host header alters the cached response,
    causing subsequent innocent requests without the header to receive the poisoned output.
    """
    runner.start_servers(upstream_mode="vulnerable", proxy_strip_headers=False)

    # 1. Clear any prior cache
    requests.get(f"{sim_config.cache_proxy_url}/cache/purge")

    # 2. Attacker sends unkeyed header
    attacker_origin = f"{sim_config.HOST}:{sim_config.ATTACKER_ORIGIN_PORT}"
    headers = {"X-Forwarded-Host": attacker_origin}
    atk_resp = requests.get(f"{sim_config.cache_proxy_url}/", headers=headers)

    assert atk_resp.status_code == 200
    assert atk_resp.headers.get("X-Cache") == "MISS"
    script_src = runner.extract_script_src(atk_resp.text)
    assert attacker_origin in script_src, f"Expected {attacker_origin} in script src, got {script_src}"

    # 3. Victim sends request with NO malicious headers
    victim_resp = requests.get(f"{sim_config.cache_proxy_url}/")
    assert victim_resp.status_code == 200
    assert victim_resp.headers.get("X-Cache") == "HIT"
    victim_src = runner.extract_script_src(victim_resp.text)

    # Assert that the innocent victim was served the attacker's script reference!
    assert attacker_origin in victim_src
    assert victim_src == f"http://{attacker_origin}/static/app.js"

    # 4. Fetch the poisoned script to confirm canary payload delivery
    canary_resp = requests.get(victim_src)
    assert canary_resp.status_code == 200
    assert "__POISONED_CANARY__" in canary_resp.text


def test_edge_header_stripping_remediation(runner, sim_config):
    """
    Verifies that when the edge proxy is configured to strip unkeyed forwarding headers,
    the upstream server never receives the attacker's malicious header.
    """
    runner.start_servers(upstream_mode="vulnerable", proxy_strip_headers=True)
    requests.get(f"{sim_config.cache_proxy_url}/cache/purge")

    attacker_origin = f"{sim_config.HOST}:{sim_config.ATTACKER_ORIGIN_PORT}"
    headers = {"X-Forwarded-Host": attacker_origin}
    resp = requests.get(f"{sim_config.cache_proxy_url}/", headers=headers)

    assert resp.status_code == 200
    script_src = runner.extract_script_src(resp.text)

    # Attacker origin should NOT be present because proxy stripped it
    assert attacker_origin not in script_src


def test_upstream_canonical_host_and_csp_hardening(runner, sim_config):
    """
    Verifies that when upstream is in hardened mode:
    1. It ignores unvalidated headers and binds to canonical asset domain.
    2. It sends Content-Security-Policy restricting script origins.
    3. Innocent victims receive protected responses.
    """
    runner.start_servers(upstream_mode="hardened", proxy_strip_headers=False)
    requests.get(f"{sim_config.cache_proxy_url}/cache/purge")

    attacker_origin = f"{sim_config.HOST}:{sim_config.ATTACKER_ORIGIN_PORT}"
    headers = {"X-Forwarded-Host": attacker_origin}
    resp = requests.get(f"{sim_config.cache_proxy_url}/", headers=headers)

    assert resp.status_code == 200
    script_src = runner.extract_script_src(resp.text)

    # In hardened mode, upstream uses canonical static host
    assert attacker_origin not in script_src
    assert sim_config.CANONICAL_STATIC_HOST in script_src

    # Verify defensive headers
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert f"script-src 'self' http://{sim_config.CANONICAL_STATIC_HOST}" in csp
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"


def test_hardened_cache_keys(runner, sim_config):
    """
    Verifies that when harden_keys=True, requests with different X-Forwarded-Host
    generate distinct cache keys, preventing cross-tenant or cross-user collisions.
    """
    runner.start_servers(upstream_mode="vulnerable", proxy_strip_headers=False, harden_keys=True)
    requests.get(f"{sim_config.cache_proxy_url}/cache/purge")

    # Attacker request with X-Forwarded-Host
    attacker_origin = f"{sim_config.HOST}:{sim_config.ATTACKER_ORIGIN_PORT}"
    atk_resp = requests.get(
        f"{sim_config.cache_proxy_url}/",
        headers={"X-Forwarded-Host": attacker_origin},
    )
    atk_key = atk_resp.headers.get("X-Cache-Key")
    assert f"XFH:{attacker_origin}" in atk_key

    # Innocent victim request without header
    victim_resp = requests.get(f"{sim_config.cache_proxy_url}/")
    victim_key = victim_resp.headers.get("X-Cache-Key")

    assert atk_key != victim_key
    assert victim_resp.headers.get("X-Cache") == "MISS"  # Not a hit from attacker's key

