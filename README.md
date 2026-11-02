# Web Cache Poisoning Attack Simulation and Defense Framework

**A Research-Grade, Reproducible Security Simulation of an Unkeyed Header Injection Vulnerability (CVSS 8.6)**

---

> [!IMPORTANT]
> **Vulnerability Classification:** CWE-444 (Inconsistent Interpretation of HTTP Requests) / CWE-79 (Improper Neutralization of Input During Web Page Generation) / CWE-610 (Externally Controlled Reference to a Resource in Another Sphere)  
> **CVSS v3.1 Base Score:** **8.6 (High / Critical)** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`  
> **Operational Scenario:** Operation Canary Poison (*Apex Global Financial Trading Portal*)  
> **Target Environment:** Python 3.9+ Multi-Tier Microservices with Automated Test Suite  

---

## 1. Executive Summary

Web Cache Poisoning is an advanced architectural vulnerability wherein an attacker exploits discrepancies between how an HTTP caching proxy (CDN, reverse proxy) hashes incoming requests and how the backend upstream server interprets them.

By manipulating **unkeyed inputs**—request components that the cache ignores when determining cache equivalency—an attacker elicits a malicious or contaminated response from the origin server. If the edge cache stores this response under a clean, shared cache key, the contaminated payload is served to subsequent legitimate users without requiring any direct interaction between the attacker and the victims.

This framework provides an end-to-end, multi-tier simulation environment comprising an Edge Reverse Proxy Cache, an Upstream Enterprise Application, and an Attacker Origin Server. It models the complete vulnerability lifecycle: reconnaissance, cache key collision, downstream victim compromise, and verified enterprise defense-in-depth remediation.

---

## 2. Theoretical Foundations and Cache Key Mechanics

### 2.1 The Mathematics of Cache Keys

In accordance with RFC 7234 (HTTP/1.1 Caching), an HTTP intermediary optimizes bandwidth and latency by serving stored responses to equivalent requests. To identify equivalence, the cache hashes a deterministic subset of request parameters known as the **Cache Key**:

$$\text{Cache Key} = \text{HTTP Method} \mathbin{\Vert} \text{Host Header} \mathbin{\Vert} \text{Request Path and Query}$$

Any component of the incoming HTTP request that is **excluded** from this hash function is classified as **unkeyed**.

```
   INCOMING HTTP REQUEST
   ┌─────────────────────────────────────────────────────────────┐
   │ GET / HTTP/1.1                                              │ ──► KEYED   (Included in Cache Key)
   │ Host: portal.apex-global-fin.internal:8880                  │ ──► KEYED   (Included in Cache Key)
   │ User-Agent: Mozilla/5.0 ...                                 │ ──► UNKEYED (Ignored by Cache)
   │ Accept-Encoding: gzip, deflate                              │ ──► UNKEYED (Ignored by Cache)
   │ X-Forwarded-Host: attacker.hostile-origin.internal:8882     │ ──► UNKEYED (Ignored by Cache) ◄── VULNERABILITY VECTOR
   │ Cookie: session_id=...                                      │ ──► UNKEYED (Ignored by Cache)
   └─────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                   COMPUTED EDGE CACHE HASH KEY:
                   [GET:portal.apex-global-fin.internal:8880:/]
```

### 2.2 Keyed vs. Unkeyed Component Matrix

| Request Attribute | Typical Cache Key Status | Risk Level | Exploitation Vector / Architectural Role |
|:---|:---:|:---:|:---|
| **HTTP Request Line (Method)** | **Keyed** | Low | Restricts cache collisions to identical HTTP verbs (`GET`, `HEAD`). |
| **Request Host Header** | **Keyed** | Medium | Isolates cache buckets across virtual hosts and domains. |
| **Request URI & Query** | **Keyed** | Medium | Identifies target route. Can be targeted by query parameter cloaking. |
| **`X-Forwarded-Host`** | **Unkeyed** | **Critical** | Overrides dynamic resource resolution in template engines. |
| **`X-Forwarded-Scheme` / `-Proto`** | **Unkeyed** | **High** | Forces protocol downgrades or cache-poisoned HTTP-to-HTTPS redirects. |
| **`X-Original-URL` / `X-Rewrite-URL`** | **Unkeyed** | **High** | Alters upstream routing while cache keys on the edge path. |
| **Client Headers / Cookies** | **Unkeyed** | Medium | Ignored by default; can trigger stored reflected XSS if processed dynamically. |

---

## 3. Operational Scenario: Operation Canary Poison

### 3.1 Target Organization Profile
* **Entity:** Apex Global Financial (*Enterprise FinTech & Institutional Brokerage*)
* **Critical Asset:** High-Frequency Trading & Banking Dashboard (`http://127.0.0.1:8880/`)
* **Concurrency:** 65,000 active sessions/minute during market opening (09:30 EST)
* **Architectural Stack:** Edge Reverse Proxy (Port 8880) fronting an internal Application Microservice Cluster (Port 8881).

### 3.2 The Business Need and The Developer Flaw
To safeguard the backend database and API clusters from being overwhelmed by market-open traffic surges, DevOps deployed an Edge Caching Reverse Proxy with a 30-second TTL on the root dashboard (`Cache-Control: public, max-age=30`).

To support continuous integration across multiple staging clusters, developer sandboxes, and CDN mirrors without hardcoding static asset origins, application developers implemented dynamic host resolution:

```python
# Upstream Application Dynamic Resolution (core/upstream_app.py)
forwarded_host = request.headers.get("X-Forwarded-Host")
request_host = request.headers.get("Host")
script_origin = forwarded_host if forwarded_host else request_host

# Renders dynamic HTML template:
# <script src="http://{script_origin}/static/app.js"></script>
```

### 3.3 The Architectural Blindspot
The edge caching proxy forwards client headers upstream, but computes its cache key based strictly on `METHOD:HOST:PATH`. The `X-Forwarded-Host` header is completely unkeyed. 

Consequently, an attacker who supplies `X-Forwarded-Host: 127.0.0.1:8882` forces the backend to generate HTML pointing to the attacker's server. The proxy then caches this poisoned HTML under the clean key `GET:127.0.0.1:8880:/`, delivering the attacker's script to every subsequent innocent visitor.

---

## 4. System Architecture and Interconnection Diagram

The simulation environment consists of three decoupled HTTP services and an automated orchestration engine:

```
+─────────────────────────────────────────────────────────────────────────────+
|                         SIMULATION SYSTEM TOPOLOGY                          |
+─────────────────────────────────────────────────────────────────────────────+

   Innocent Clients (Alice, Bob, Charlie)         Threat Actor (Mallory)
                     │                                      │
                     │ HTTP Port 8880                       │ Injected Header
                     ▼                                      ▼
   ┌──────────────────────────────────────────────────────────────┐
   │              EDGE CACHING REVERSE PROXY                      │
   │              File: core/cache_proxy.py                       │
   │              Port: 8880 | Cache TTL: 30s                     │
   │                                                              │
   │  • Computes Cache Key: METHOD + Host + Path                  │
   │  • Unkeyed: X-Forwarded-Host (Ignored in key)                │
   │  • Cache Store: In-Memory TTL Store (core/cache_proxy.py)    │
   └──────────────────────────────┬───────────────────────────────┘
                                  │
                                  │ Cache Miss: Forwards Request
                                  ▼
   ┌──────────────────────────────────────────────────────────────┐
   │             UPSTREAM ENTERPRISE APPLICATION                  │
   │             File: core/upstream_app.py                       │
   │             Port: 8881                                       │
   │                                                              │
   │  • Vulnerable Mode: Trusts X-Forwarded-Host for <script src> │
   │  • Hardened Mode: Canonical Host Binding + CSP Directives    │
   │  • Legitimate Bundle: /static/app.js                         │
   └──────────────────────────────────────────────────────────────┘
                                  ▲
                                  │ Browser fetches script
   ┌──────────────────────────────┴───────────────────────────────┐
   │                 MOCK ATTACKER ORIGIN                         │
   │                 File: core/mock_attacker_origin.py           │
   │                 Port: 8882                                   │
   │                                                              │
   │  • Serves Hostile Verification Canary (/static/app.js)       │
   │  • Logs Victim Compromise Events (access_logs)               │
   └──────────────────────────────────────────────────────────────┘
```

---

## 5. File-by-File Technical Deep Dive

Every component within the workspace fulfills a distinct responsibility in the simulation pipeline:

### 5.1 [`config.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/config.py)
* **Function:** Global configuration repository.
* **Internal Mechanics:** Defines the [`SimulationConfig`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/config.py#L11) dataclass. Stores loopback IP addresses, dedicated service ports (`8880` for Cache Proxy, `8881` for Upstream, `8882` for Attacker Origin), cache parameters (`DEFAULT_CACHE_TTL = 30`), and canonical hostname allowlists.
* **Role in Pipeline:** Imported by all microservices, tests, and scenario runners to ensure synchronized socket addressing without hardcoded values.

### 5.2 [`core/cache_proxy.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/core/cache_proxy.py)
* **Function:** Reverse proxy edge cache engine.
* **Internal Mechanics:**
  * [`CacheEntry`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/core/cache_proxy.py#L23): Encapsulates cached status codes, response headers, binary body, and monotonic timestamp calculation for TTL expiration.
  * [`CacheStore`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/core/cache_proxy.py#L42): Thread-safe in-memory cache with eviction and diagnostic counters (hits/misses).
  * [`CacheProxyRequestHandler`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/core/cache_proxy.py#L72): Inspects incoming GET requests, computes `METHOD:HOST:PATH`, checks the store, proxies cache misses to `127.0.0.1:8881`, and attaches cache diagnostic headers (`X-Cache`, `X-Cache-Key`, `Age`).
  * [`ProxyCacheServer`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/core/cache_proxy.py#L214): Multi-threaded HTTP server daemon running on port 8880.
* **Remediation Support:** Features `strip_unkeyed_headers=True` to filter out client-supplied forwarding headers at the edge, and `harden_keys=True` to expand the cache key if dynamic host handling is required.

### 5.3 [`core/upstream_app.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/core/upstream_app.py)
* **Function:** Upstream banking application backend.
* **Internal Mechanics:**
  * [`UpstreamRequestHandler`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/core/upstream_app.py#L17):
    * Route `/`: Renders corporate banking portal HTML.
    * Route `/static/app.js`: Serves the authentic application runtime.
    * Route `/health`: Microservice health probe.
  * [`UpstreamServer`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/core/upstream_app.py#L143): Multi-threaded HTTP server daemon running on port 8881.
* **Dual Operation Modes:**
  * `mode="vulnerable"`: Reads `X-Forwarded-Host` without sanitization, dynamically rendering `<script src="http://{script_origin}/static/app.js">`.
  * `mode="hardened"`: Enforces `config.CANONICAL_STATIC_HOST`, attaches strict `Content-Security-Policy` directives, emits `Vary: X-Forwarded-Host`, and enables `X-Content-Type-Options: nosniff`.

### 5.4 [`core/mock_attacker_origin.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/core/mock_attacker_origin.py)
* **Function:** External adversary hosting infrastructure.
* **Internal Mechanics:**
  * [`MockAttackerRequestHandler`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/core/mock_attacker_origin.py#L19): Serves a safe proof-of-concept verification canary script (`window.__POISONED_CANARY__ = true;`) at `/static/app.js`.
  * [`MockAttackerServer`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/core/mock_attacker_origin.py#L86): Multi-threaded HTTP server daemon on port 8882. Maintains a thread-safe `access_logs` buffer recording IP and User-Agent telemetry whenever a victim client fetches the canary asset.

### 5.5 [`sim/scenarios.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/sim/scenarios.py)
* **Function:** Test orchestrator and lifecycle engine.
* **Internal Mechanics:**
  * [`SimulationScenarioRunner`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/sim/scenarios.py#L22): Manages startup, socket readiness polling, execution, and teardown of the three services.
  * Methods `run_phase_1_baseline()`, `run_phase_2_poisoning()`, `run_phase_3_impact()`, and `run_phase_4_remediation()` execute programmatic requests using the `requests` library and parse response HTML using regular expressions to evaluate asset origins.

### 5.6 [`sim/visualizer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/sim/visualizer.py)
* **Function:** Terminal UI and visual telemetry renderer.
* **Internal Mechanics:** Leverages the `rich` library to render stylized ASCII banners, scenario case file briefings, structured transaction audit tables, and CVSS vulnerability cards across Windows, Linux, and macOS consoles with automatic UTF-8 reconfiguration.

### 5.7 [`run_simulation.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/run_simulation.py)
* **Function:** Main CLI entry point.
* **Internal Mechanics:** Initializes the simulation environment, prints the operational scenario briefing, steps through Phases 1 through 4 sequentially, handles keyboard interrupts gracefully, and guarantees clean server thread termination.

### 5.8 [`tests/test_cache_poisoning_sim.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/tests/test_cache_poisoning_sim.py)
* **Function:** Automated integration test suite.
* **Internal Mechanics:** Implements 5 Pytest test cases validating cache MISS/HIT transitions, unkeyed reflection, victim pollution, edge header stripping, and CSP canonical resolution against dedicated test ports (`8980`, `8981`, `8982`).

### 5.9 [`SCENARIO.md`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/SCENARIO.md)
* **Function:** Operational red-team/blue-team incident narrative.
* **Internal Mechanics:** Details the organizational profile of Apex Global Financial, chronological incident timeline (09:00 - 09:15), CVSS 3.1 score decomposition, and blue team SOC incident response playbook.

---

## 6. Simulation Execution Phases

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       4-PHASE SIMULATION LIFECYCLE                          │
├─────────────────────────────────────────────────────────────────────────────┤
│ Phase 1: Baseline Traffic Analysis                                          │
│ • User Alice requests GET /  ──► Cache MISS ──► Cached authentic response   │
│ • User Bob requests GET /    ──► Cache HIT  ──► Served from Edge Cache      │
├─────────────────────────────────────────────────────────────────────────────┤
│ Phase 2: Unkeyed Header Injection & Cache Desynchronization                 │
│ • Attacker Mallory sends: X-Forwarded-Host: 127.0.0.1:8882                  │
│ • Edge Proxy ignores header in key: Key = [GET:127.0.0.1:8880:/]            │
│ • Upstream reflects attacker host into <script src="...">                   │
│ • Proxy stores poisoned HTML under clean key (TTL: 30s)                     │
├─────────────────────────────────────────────────────────────────────────────┤
│ Phase 3: High-Severity Impact Verification (Downstream Victims)             │
│ • User Charlie sends standard GET / with NO malicious headers               │
│ • Edge Proxy matches clean key ──► Serves poisoned response (Cache HIT)     │
│ • Charlie's browser executes script from Attacker Origin (Port 8882)        │
├─────────────────────────────────────────────────────────────────────────────┤
│ Phase 4: Remediation & Defense-in-Depth Verification                        │
│ • Edge Proxy: Drops X-Forwarded-* headers from untrusted clients            │
│ • Upstream App: Locks script origin to canonical domain + applies CSP       │
│ • Re-attack attempt fails ──► Authentic assets served to subsequent users   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Execution and Verification Guide

### 7.1 Prerequisites and Installation
* Python 3.9 or higher
* Recommended virtual environment

Install the project dependencies from [`requirements.txt`](file:///c:/Users/haziq/OneDrive/Documents/projects/attack%20sim/requirements.txt):

```powershell
pip install -r requirements.txt
```

### 7.2 Running the Interactive Visual Simulation
To execute the complete 4-phase simulation with colorized terminal telemetry:

```powershell
python run_simulation.py
```

### 7.3 Running the Automated Regression Test Suite
To execute the automated Pytest test suite and verify individual security assertions:

```powershell
pytest tests/test_cache_poisoning_sim.py -v
```

#### Test Suite Assertion Summary:
* `test_baseline_caching_behavior`: Verifies normal Cache MISS on initial request and Cache HIT on second request.
* `test_unkeyed_header_cache_poisoning`: Verifies that `X-Forwarded-Host` alters cached HTML and poisons headerless victim requests.
* `test_edge_header_stripping_remediation`: Verifies that edge proxy header stripping prevents unkeyed headers from reaching upstream.
* `test_upstream_canonical_host_and_csp_hardening`: Verifies that upstream enforces canonical domains and attaches CSP headers.
* `test_hardened_cache_keys`: Verifies that key expansion separates unkeyed headers into distinct cache buckets.

---

## 8. Enterprise Defense-in-Depth Blueprint

Remediating Web Cache Poisoning requires defensive controls across all architectural tiers:

### 8.1 Tier 1: Edge Proxy Header Filtering
Configure edge reverse proxies and CDNs (Cloudflare, AWS CloudFront, Akamai, Nginx) to strip or sanitize incoming forwarding headers from external clients:

```nginx
# Nginx Edge Proxy Hardening
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
```

### 8.2 Tier 2: Upstream Canonical Domain Enforcement
Never construct static resource URLs, import tags, or redirections dynamically using client-supplied headers. Enforce canonical absolute URLs or relative paths:

```python
# SECURE BACKEND IMPLEMENTATION
CANONICAL_CDN_ORIGIN = "https://cdn.apex-global-fin.internal"
script_tag = f'<script src="{CANONICAL_CDN_ORIGIN}/static/app.js"></script>'
```

### 8.3 Tier 3: Protocol Cache Key Expansion (`Vary`)
If a backend application legitimately requires response variations based on a request header, instruct caching intermediaries to incorporate that header into the cache key:

```http
Vary: X-Forwarded-Host, User-Agent
```

### 8.4 Tier 4: Client-Side Content Security Policy (CSP)
Deploy restrictive Content Security Policies to block execution of scripts loaded from unapproved origins, ensuring client-side safety even if a cache entry is compromised:

```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.apex-global-fin.internal; object-src 'none';
```

---

## 9. Academic and Industry References

1. **Kettle, James.** (2018). *Practical Web Cache Poisoning: Redefining the attack surface.* PortSwigger Web Security Research.
2. **Kettle, James.** (2020). *Web Cache Entanglement: Novel Pathways to Poisoning.* PortSwigger Web Security Research.
3. **Fielding, R., Nottingham, M., & Reschke, J.** (2014). *Hypertext Transfer Protocol (HTTP/1.1): Caching.* RFC 7234, Internet Engineering Task Force (IETF).
4. **MITRE Corporation.** (2024). *CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling').* Common Weakness Enumeration.
5. **OWASP Foundation.** (2021). *OWASP Top 10 - A05:2021 Security Misconfiguration.* Open Web Application Security Project.
