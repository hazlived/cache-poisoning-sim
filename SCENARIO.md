# Scenario Briefing: Operation Canary Poison

**Threat Model & Incident Scenario Document for High-Severity Web Cache Poisoning**

---

## 1. Target Organization Profile

* **Organization:** Apex Global Financial (*Enterprise FinTech & Institutional Trading*)
* **Critical Asset:** Customer Banking & Trading Portal Homepage (`https://portal.apex-global-fin.internal/`)
* **Daily Active Users:** 85,000+ traders, institutional investors, and retail banking clients
* **Peak Traffic:** 60,000 requests/minute during market opening bell (09:30 EST)

---

## 2. Business Context & Architectural Motivation

To protect origin application servers from being overwhelmed by traffic spikes during market volatility, Apex Global's DevOps team placed an **Edge Caching Reverse Proxy (CDN)** in front of the application cluster.

### The Caching Policy
* **Cached Endpoints:** Static assets (`/static/*`) and the main portal dashboard shell (`/`).
* **Cache Control:** `Cache-Control: public, max-age=30` (30-second window to balance real-time dashboard updates with cache offload efficiency).
* **Cache Key Formula:**
  $$\text{Cache Key} = \text{HTTP Method} + \text{Host Header} + \text{Request URI}$$

### The Developer's Fatal Flaw
To simplify multi-environment deployments across Development, Staging, Multi-Region Clusters, and CDN Mirrors without maintaining hardcoded asset URLs, the backend template engine derives static asset origins dynamically from incoming forwarding headers:
```python
# Vulnerable Backend Implementation in upstream_app.py:
forwarded_host = request.headers.get("X-Forwarded-Host")
request_host = request.headers.get("Host")
script_origin = forwarded_host if forwarded_host else request_host

# Renders:
# <script src="http://{script_origin}/static/app.js"></script>
```

### The Architectural Blindspot
The edge caching proxy strips neither `X-Forwarded-Host` nor includes it in its cache key calculation. The proxy considers `X-Forwarded-Host` to be an **unkeyed header**. It forwards the header upstream, but hashes the incoming request based solely on `GET:portal.apex-global-fin.internal:/`.

---

## 3. Threat Actor Profile & Objectives

* **Threat Actor:** Adversary Mallory (*FIN-Aligned Cybercrime Syndicate*)
* **Motivation:** High-value session hijacking, financial transaction tampering, and credential harvesting targeting institutional trading desks.
* **Attack Constraints:**
  * No credentials or internal network access.
  * Web Application Firewall (WAF) blocks traditional `<script>` and `javascript:` inline payloads in request bodies and query parameters.
  * Needs a distribution mechanism with a massive blast radius.

---

## 4. Chronological Incident Scenario (09:00 - 09:15)

```
09:00:00 [Normal Operations]
    Alice and Bob browse to the banking portal.
    Edge cache serves legitimate responses referencing authentic scripts.

09:05:00 [Attacker Reconnaissance]
    Mallory identifies that the portal supports unkeyed X-Forwarded-Host headers
    and reflects them into script tags without sanitization.

09:05:30 [Weaponization & Staging]
    Mallory deploys an external asset hosting origin (Port 8882) hosting
    a trojanized/canary version of app.js.

09:06:00 [The Poisoning Strike]
    Mallory sends a single HTTP request to the Edge Proxy (Port 8880) targeting /
    with header: X-Forwarded-Host: 127.0.0.1:8882.
    The proxy experiences a Cache Miss, forwards the request upstream,
    and caches the poisoned response under the clean cache key: GET:127.0.0.1:8880:/.

09:06:01 - 09:06:31 [Mass Propagation & Victim Compromise]
    Over 5,000 legitimate users (including Victim Charlie) browse to the portal.
    The Edge Cache serves the poisoned response (Cache HIT).
    Every victim browser executes Mallory's script in the context of their
    authenticated portal session!

09:10:00 [Incident Response & Hardening]
    Apex Security Operations Center (SOC) deploys emergency defense:
    1. Edge Proxy strips untrusted forwarding headers.
    2. Upstream locks asset imports to canonical domain.
    3. Strict Content Security Policy (CSP) deployed.
    Attacker re-attempt is completely neutralized.
```

---

## 5. Threat Metrics & CVSS v3.1 Analysis

* **CVSS Score:** **8.6 (High / Critical)**
* **Vector String:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`
* **Why the Severity is High:**
  * **Exploitation requires 1 single request:** The attacker does not need to phish users individually or send malicious links.
  * **Zero Privileges Required:** Can be triggered from any unauthenticated IP on the internet.
  * **Changed Scope ($S:C$):** The vulnerability originates in the infrastructure/cache layer, but the impact compromises the browser DOM and security context of every downstream client.
  * **Bypasses Traditional WAFs:** The request contains no `<script>` tags, SQL syntax, or known attack signatures—only a seemingly harmless standard HTTP header.

---

## 6. Blue Team Incident Response & Hardening Guide

| Layer | Remediation Measure | Implementation |
|---|---|---|
| **Edge Proxy / CDN** | Strip untrusted forwarding headers | Configure CDN rules to drop `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL` from external clients. |
| **Edge Proxy / CDN** | Cache Key Normalization | If dynamic behavior is required, expand cache key or strictly honor `Vary: X-Forwarded-Host`. |
| **Upstream Application** | Canonical Domain Binding | Hardcode canonical asset domains (`https://cdn.apex-global-fin.internal/`) in templates; never trust request headers. |
| **Browser Context** | Content Security Policy (CSP) | Add `script-src 'self' https://cdn.apex-global-fin.internal;` to prevent execution of scripts loaded from unapproved origins. |

