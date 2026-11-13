"""
Integration tests for the Web Cache Poisoning Laboratory UI Server.
Verifies static asset delivery, REST API endpoints, mode switching,
custom request probing, and simulated victim DOM verification.
"""

from http.server import ThreadingHTTPServer
import threading
import time
import pytest
import requests

from config import SimulationConfig
from ui_server import SimulationEnvironmentManager, LabUIRequestHandler


@pytest.fixture(scope="module")
def ui_test_server():
    # Use dedicated ports for UI test fixture to avoid collisions
    test_config = SimulationConfig(
        CACHE_PROXY_PORT=8780,
        UPSTREAM_PORT=8781,
        ATTACKER_ORIGIN_PORT=8782,
        DEFAULT_CACHE_TTL=10,
    )

    env_mgr = SimulationEnvironmentManager(test_config)
    env_mgr.start()

    # Temporarily monkey-patch global manager and default config in handler module
    import ui_server
    orig_env = ui_server.ENV_MANAGER
    orig_cfg = ui_server.DEFAULT_CONFIG
    ui_server.ENV_MANAGER = env_mgr
    ui_server.DEFAULT_CONFIG = test_config

    server_address = ("127.0.0.1", 8788)
    httpd = ThreadingHTTPServer(server_address, LabUIRequestHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.5)

    yield "http://127.0.0.1:8788"

    httpd.shutdown()
    httpd.server_close()
    env_mgr.stop()
    ui_server.ENV_MANAGER = orig_env
    ui_server.DEFAULT_CONFIG = orig_cfg


def test_ui_static_assets(ui_test_server):
    """Verifies that index.html, style.css, and app.js are served with correct MIME types."""
    # 1. HTML
    r_html = requests.get(f"{ui_test_server}/")
    assert r_html.status_code == 200
    assert "text/html" in r_html.headers.get("Content-Type", "")
    assert "Web Cache Poisoning Laboratory" in r_html.text

    # 2. CSS
    r_css = requests.get(f"{ui_test_server}/style.css")
    assert r_css.status_code == 200
    assert "text/css" in r_css.headers.get("Content-Type", "")

    # 3. JS
    r_js = requests.get(f"{ui_test_server}/app.js")
    assert r_js.status_code == 200
    assert "javascript" in r_js.headers.get("Content-Type", "")


def test_ui_api_status_and_mode_toggle(ui_test_server):
    """Verifies cluster health reporting and seamless mode switching."""
    # Status check
    r_status = requests.get(f"{ui_test_server}/api/status")
    assert r_status.status_code == 200
    data = r_status.json()
    assert data["proxy_online"] is True
    assert data["upstream_online"] is True
    assert data["attacker_online"] is True

    # Mode toggle to hardened
    r_mode = requests.post(f"{ui_test_server}/api/mode", json={"mode": "hardened"})
    assert r_mode.status_code == 200
    assert r_mode.json()["mode"] == "hardened"

    # Mode toggle back to vulnerable
    r_mode2 = requests.post(f"{ui_test_server}/api/mode", json={"mode": "vulnerable"})
    assert r_mode2.status_code == 200
    assert r_mode2.json()["mode"] == "vulnerable"


def test_ui_api_phases_and_custom_probe(ui_test_server):
    """Verifies scenario phase execution and custom HTTP request evaluation."""
    # Run Phase 1
    r_p1 = requests.post(f"{ui_test_server}/api/phase/1")
    assert r_p1.status_code == 200
    p1_txs = r_p1.json()["transactions"]
    assert len(p1_txs) == 2
    assert p1_txs[0]["cache_status"] == "MISS"
    assert p1_txs[1]["cache_status"] == "HIT"

    # Purge cache
    r_purge = requests.post(f"{ui_test_server}/api/cache/purge")
    assert r_purge.status_code == 200

    # Custom request injection
    r_probe = requests.post(f"{ui_test_server}/api/custom-request", json={
        "method": "GET",
        "path": "/",
        "headers": {"X-Forwarded-Host": "127.0.0.1:8782"},
    })
    assert r_probe.status_code == 200
    probe_data = r_probe.json()
    assert "8782" in probe_data["script_source"]
    assert probe_data["is_poisoned"] is True

    # Check cache table entries
    r_entries = requests.get(f"{ui_test_server}/api/cache/entries")
    assert r_entries.status_code == 200
    entries = r_entries.json()["entries"]
    assert len(entries) >= 1
    assert any(e["is_poisoned"] for e in entries)

    # Simulated victim view
    r_vic = requests.get(f"{ui_test_server}/api/simulate-victim")
    assert r_vic.status_code == 200
    vic_data = r_vic.json()
    assert vic_data["is_poisoned"] is True
    assert vic_data["cache_status"] == "HIT"
