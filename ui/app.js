/**
 * Web Cache Poisoning Laboratory Client Application
 * Neo-Brutalist interactive console with live attack flow animations,
 * phase-by-phase visual simulation engine, and real-time telemetry.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Application State
  const state = {
    currentPhase: 1,
    mode: 'vulnerable',
    isAnimating: false,
    autoRefreshInterval: null,
  };

  // DOM Elements: Top Navigation & Status
  const elStatusProxy = document.getElementById('status-proxy');
  const elStatusUpstream = document.getElementById('status-upstream');
  const elStatusAttacker = document.getElementById('status-attacker');
  const elModeBadge = document.getElementById('mode-badge');
  const elBtnToggleMode = document.getElementById('btn-toggle-mode');
  const elBtnPurgeCache = document.getElementById('btn-purge-cache');
  const elUpstreamModeTag = document.getElementById('upstream-mode-tag');

  // Telemetry Metrics
  const elMetricHits = document.getElementById('metric-hits');
  const elMetricMisses = document.getElementById('metric-misses');
  const elMetricKeys = document.getElementById('metric-keys');

  // Animation & Topology Pipeline Elements
  const elAnimationTicker = document.getElementById('animation-ticker');
  const elBtnPlayAnimation = document.getElementById('btn-play-animation');
  const elBtnResetAnimation = document.getElementById('btn-reset-animation');
  const elNodeClient = document.getElementById('node-client');
  const elNodeProxy = document.getElementById('node-proxy');
  const elNodeUpstream = document.getElementById('node-upstream');
  const elNodeAttacker = document.getElementById('node-attacker');
  const elArrowClientProxy = document.getElementById('arrow-client-proxy');
  const elArrowProxyUpstream = document.getElementById('arrow-proxy-upstream');
  const elPacketTracer = document.getElementById('packet-tracer');
  const elPacketText = document.getElementById('packet-text');

  // Scenario Stepper Elements
  const elStepProgressBar = document.getElementById('step-progress-bar');
  const elPhaseButtons = document.querySelectorAll('.btn-phase');
  const elPhaseContextTitle = document.getElementById('phase-context-title');
  const elPhaseContextDesc = document.getElementById('phase-context-desc');
  const elBtnRunCurrentPhase = document.getElementById('btn-run-current-phase');
  const elBtnAnimateCurrentPhase = document.getElementById('btn-animate-current-phase');
  const elBtnRunAll = document.getElementById('btn-run-all');
  const elTelemetryLog = document.getElementById('telemetry-log-container');
  const elBtnClearLogs = document.getElementById('btn-clear-logs');

  // Interactive Workbench Form & Result Elements
  const elWorkbenchForm = document.getElementById('workbench-form');
  const elReqMethod = document.getElementById('req-method');
  const elReqPath = document.getElementById('req-path');
  const elReqHeaders = document.getElementById('req-headers');
  const elProbeBadgeCache = document.getElementById('probe-badge-cache');
  const elProbeResStatus = document.getElementById('probe-res-status');
  const elProbeResTime = document.getElementById('probe-res-time');
  const elProbeResKey = document.getElementById('probe-res-key');
  const elProbeResScript = document.getElementById('probe-res-script');
  const elProbeVerdictBox = document.getElementById('probe-verdict-box');
  const elProbeVerdictText = document.getElementById('probe-verdict-text');
  const elProbeRawHeaders = document.getElementById('probe-raw-headers');

  // Cache Table & Simulated Viewport
  const elCacheTableBody = document.getElementById('cache-table-body');
  const elBtnRefreshCache = document.getElementById('btn-refresh-cache');
  const elBtnRefreshView = document.getElementById('btn-refresh-view');
  const elBrowserContentArea = document.getElementById('browser-content-area');
  const elClientScriptVal = document.getElementById('client-script-val');
  const elMockBrowser = document.querySelector('.mock-browser');

  // Phase Descriptions
  const phases = {
    1: {
      title: 'Phase 1: Baseline Traffic Analysis',
      desc: 'Innocent client Alice accesses the banking dashboard. The edge proxy checks the cache key, encounters a MISS, requests the asset from upstream, and stores the authentic response. Client Bob visits next and receives a clean Cache HIT.',
    },
    2: {
      title: 'Phase 2: Unkeyed Header Injection & Cache Desynchronization',
      desc: 'Attacker Mallory targets the homepage with unkeyed header "X-Forwarded-Host: 127.0.0.1:8882". The edge proxy excludes this header from its cache key calculation, but forwards it upstream. The upstream dynamically reflects it into the script tag, and the edge proxy caches the poisoned output under the clean key.',
    },
    3: {
      title: 'Phase 3: High-Severity Impact on Innocent Victims',
      desc: 'Innocent client Charlie visits the homepage using a standard browser without custom headers. The edge proxy serves the cached response (Cache HIT). Charlie\'s browser executes the script from the attacker origin (:8882), demonstrating Stored Cross-Site Scripting via the CDN cache.',
    },
    4: {
      title: 'Phase 4: Remediation & Defense-in-Depth Verification',
      desc: 'Applies enterprise defense layers: edge proxy header stripping, upstream canonical asset binding, and Content-Security-Policy (CSP). The attacker re-attempts the injection, but the proxy neutralizes the header and downstream clients remain safe.',
    },
  };

  // Initialization
  init();

  function init() {
    setupEventListeners();
    fetchStatus();
    fetchCacheEntries();
    simulateVictimView();

    // Auto-refresh metrics every 4 seconds
    state.autoRefreshInterval = setInterval(() => {
      fetchStatus(true);
      fetchCacheEntries(true);
    }, 4000);
  }

  function setupEventListeners() {
    // Mode toggle
    elBtnToggleMode.addEventListener('click', toggleHardeningMode);

    // Purge cache
    elBtnPurgeCache.addEventListener('click', purgeCache);

    // Top Animation controls
    elBtnPlayAnimation.addEventListener('click', playFullAttackAnimation);
    elBtnResetAnimation.addEventListener('click', resetAnimationFlow);

    // Phase selector tabs
    elPhaseButtons.forEach((btn) => {
      btn.addEventListener('click', () => {
        const p = parseInt(btn.dataset.phase, 10);
        selectPhase(p);
      });
    });

    // Run current phase (direct execution)
    elBtnRunCurrentPhase.addEventListener('click', () => {
      runPhase(state.currentPhase);
    });

    // Animate current phase (visual animated walkthrough)
    elBtnAnimateCurrentPhase.addEventListener('click', () => {
      animatePhase(state.currentPhase);
    });

    // Run all phases
    elBtnRunAll.addEventListener('click', runAllPhases);

    // Clear logs
    elBtnClearLogs.addEventListener('click', () => {
      elTelemetryLog.innerHTML = '<div class="log-empty-state">Audit log cleared.</div>';
    });

    // Workbench Form Submit
    elWorkbenchForm.addEventListener('submit', handleWorkbenchSubmit);

    // Presets
    document.querySelectorAll('.btn-preset').forEach((btn) => {
      btn.addEventListener('click', () => {
        applyPreset(btn.dataset.preset);
      });
    });

    // Refresh buttons
    elBtnRefreshCache.addEventListener('click', () => fetchCacheEntries());
    elBtnRefreshView.addEventListener('click', () => simulateVictimView());
  }

  function selectPhase(phaseNum) {
    state.currentPhase = phaseNum;
    elPhaseButtons.forEach((b) => {
      b.classList.toggle('active', parseInt(b.dataset.phase, 10) === phaseNum);
    });
    elPhaseContextTitle.textContent = phases[phaseNum].title;
    elPhaseContextDesc.textContent = phases[phaseNum].desc;

    // Update progress bar
    if (elStepProgressBar) {
      elStepProgressBar.className = 'step-progress-bar step-' + phaseNum;
    }
  }

  // =========================================================================
  // ANIMATION ENGINE: FLOATING PACKETS & TOPOLOGY NODES
  // =========================================================================

  function clearNodeHighlights() {
    [elNodeClient, elNodeProxy, elNodeUpstream, elNodeAttacker].forEach((n) => {
      n.classList.remove('active-packet', 'active-poison', 'active-safe', 'shield-active');
    });
    elArrowClientProxy.classList.remove('flow-active', 'flow-poison');
    elArrowProxyUpstream.classList.remove('flow-active', 'flow-poison');
    hidePacket();
  }

  function showPacket(text, typeClass, posClass) {
    elPacketText.textContent = text;
    elPacketTracer.className = `packet-tracer-badge visible ${typeClass} ${posClass}`;
  }

  function hidePacket() {
    elPacketTracer.className = 'packet-tracer-badge';
  }

  function resetAnimationFlow() {
    clearNodeHighlights();
    elAnimationTicker.textContent = 'Pipeline reset to idle state. Ready for simulation.';
    purgeCache();
  }

  function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  // =========================================================================
  // DEDICATED PHASE ANIMATIONS (PHASE 1, 2, 3, 4)
  // =========================================================================

  async function animatePhase(phaseNum) {
    if (state.isAnimating) return;
    state.isAnimating = true;

    // Visual button glow
    const activeBtn = document.querySelector(`.btn-phase[data-phase="${phaseNum}"]`);
    if (activeBtn) activeBtn.classList.add('animating');

    try {
      if (phaseNum === 1) {
        await animatePhase1();
      } else if (phaseNum === 2) {
        await animatePhase2();
      } else if (phaseNum === 3) {
        await animatePhase3();
      } else if (phaseNum === 4) {
        await animatePhase4();
      }
    } finally {
      if (activeBtn) activeBtn.classList.remove('animating');
      state.isAnimating = false;
    }
  }

  // Phase 1 Animation: Baseline Normal Traffic
  async function animatePhase1() {
    clearNodeHighlights();
    elAnimationTicker.textContent = '[PHASE 1] Step 1: Alice requests GET / -> Edge Cache checks key -> MISS!';
    showPacket('Alice: GET /', 'packet-type-clean', 'pos-client');
    elNodeClient.classList.add('active-packet');
    elArrowClientProxy.classList.add('flow-active');
    await delay(700);

    // Moves to Proxy
    showPacket('Key = [GET:portal:8880:/]', 'packet-type-clean', 'pos-proxy');
    elNodeClient.classList.remove('active-packet');
    elNodeProxy.classList.add('active-packet');
    await delay(700);

    // Moves to Upstream
    elAnimationTicker.textContent = '[PHASE 1] Step 2: Cache MISS forwarded to Upstream (:8881) -> Fetches authentic bundle.';
    showPacket('Forwarding Upstream', 'packet-type-clean', 'pos-upstream');
    elArrowProxyUpstream.classList.add('flow-active');
    elNodeUpstream.classList.add('active-safe');
    await delay(800);

    // Returns to Proxy
    elAnimationTicker.textContent = '[PHASE 1] Step 3: Upstream returns 200 OK. Edge Proxy caches authentic response (TTL: 30s).';
    showPacket('200 OK (Authentic)', 'packet-type-clean', 'pos-proxy');
    elNodeProxy.classList.add('active-safe');
    await delay(800);

    // Second client Bob visits
    elAnimationTicker.textContent = '[PHASE 1] Step 4: Bob visits GET / -> Cache HIT! Served directly from Edge memory.';
    showPacket('Bob: Cache HIT', 'packet-type-hit', 'pos-client');
    await delay(700);

    hidePacket();
    await runPhase(1, true);
    elAnimationTicker.textContent = '[PHASE 1 COMPLETE] Authentic responses cached and served from edge.';
  }

  // Phase 2 Animation: Unkeyed Header Injection & Cache Desynchronization
  async function animatePhase2() {
    clearNodeHighlights();
    elAnimationTicker.textContent = '[PHASE 2] Step 1: Attacker Mallory injects unkeyed header X-Forwarded-Host: 127.0.0.1:8882';
    elNodeClient.classList.add('active-poison');
    elArrowClientProxy.classList.add('flow-poison');
    showPacket('Mallory: Injected Header', 'packet-type-poison', 'pos-client');
    await delay(800);

    // Moves to Proxy
    elAnimationTicker.textContent = '[PHASE 2] Step 2: Edge Proxy evaluates Cache Key [GET:portal:8880:/]. Unkeyed header IGNORED in key!';
    showPacket('Key Omits X-Fwd-Host', 'packet-type-poison', 'pos-proxy');
    elNodeClient.classList.remove('active-poison');
    elNodeProxy.classList.add('active-packet');
    await delay(900);

    // Moves to Upstream
    elAnimationTicker.textContent = '[PHASE 2] Step 3: Upstream reflects hostile host into HTML: <script src="http://127.0.0.1:8882/static/app.js">';
    showPacket('Upstream Reflection', 'packet-type-poison', 'pos-upstream');
    elArrowProxyUpstream.classList.add('flow-poison');
    elNodeUpstream.classList.add('active-poison');
    await delay(900);

    // Returns to Proxy
    showPacket('Poisoned HTML', 'packet-type-poison', 'pos-proxy');
    elNodeUpstream.classList.remove('active-poison');
    elNodeProxy.classList.add('active-poison');
    elAnimationTicker.textContent = '[PHASE 2] Step 4: CRITICAL! Edge Proxy caches poisoned response under shared clean key!';
    await delay(900);

    hidePacket();
    await runPhase(2, true);
    elAnimationTicker.textContent = '[PHASE 2 COMPLETE] Cache poisoned! Next legitimate visitor will receive hostile payload.';
  }

  // Phase 3 Animation: Innocent Victim Compromise
  async function animatePhase3() {
    clearNodeHighlights();
    elAnimationTicker.textContent = '[PHASE 3] Step 1: Innocent trader Charlie sends normal GET / (NO custom headers whatsoever).';
    elNodeClient.classList.add('active-packet');
    elArrowClientProxy.classList.add('flow-active');
    showPacket('Charlie: Clean GET /', 'packet-type-clean', 'pos-client');
    await delay(700);

    // Moves to Proxy
    elAnimationTicker.textContent = '[PHASE 3] Step 2: Edge Proxy matches clean key [GET:portal:8880:/] -> Cache HIT! Returning stored response.';
    showPacket('Cache HIT (Poisoned)', 'packet-type-poison', 'pos-proxy');
    elNodeProxy.classList.add('active-poison');
    await delay(800);

    // Returns to Client
    showPacket('Hostile Asset Received', 'packet-type-poison', 'pos-client');
    elNodeClient.classList.add('active-poison');
    await delay(700);

    // Jumps to Attacker Origin (:8882)
    elAnimationTicker.textContent = '[PHASE 3] Step 3: Charlie\'s browser executes script from Attacker Origin (:8882)! Client-side compromise.';
    showPacket('Fetching Script :8882', 'packet-type-poison', 'pos-attacker');
    elNodeAttacker.classList.add('active-poison');
    await delay(700);

    // Tactile screen shake on simulated browser
    if (elMockBrowser) {
      elMockBrowser.classList.add('screen-shake');
      setTimeout(() => elMockBrowser.classList.remove('screen-shake'), 600);
    }

    hidePacket();
    await runPhase(3, true);
    await simulateVictimView();
    elAnimationTicker.textContent = '[PHASE 3 COMPLETE] Stored XSS executed in victim session. CVSS 8.6 impact demonstrated.';
  }

  // Phase 4 Animation: Defense-in-Depth Remediation
  async function animatePhase4() {
    clearNodeHighlights();
    elAnimationTicker.textContent = '[PHASE 4] Step 1: Hardening deployed -> Edge Proxy activates barrier (header strip) & Upstream enforces CSP.';
    elNodeProxy.classList.add('shield-active');
    await delay(800);

    // Attacker re-attempts
    elAnimationTicker.textContent = '[PHASE 4] Step 2: Attacker re-attempts injection with X-Forwarded-Host: 127.0.0.1:8882';
    elNodeClient.classList.add('active-poison');
    elArrowClientProxy.classList.add('flow-poison');
    showPacket('Attacker Injection', 'packet-type-poison', 'pos-client');
    await delay(700);

    // Hits Proxy Shield
    showPacket('BLOCKED: Header Dropped', 'packet-type-blocked', 'pos-proxy');
    elAnimationTicker.textContent = '[PHASE 4] Step 3: Edge Proxy strips untrusted header before upstream forwarding!';
    await delay(800);

    // Sanitized request to Upstream
    showPacket('Canonical Asset + CSP', 'packet-type-clean', 'pos-upstream');
    elNodeUpstream.classList.add('active-safe');
    await delay(700);

    // Innocent client David visits
    elAnimationTicker.textContent = '[PHASE 4] Step 4: Client David visits -> Authentic asset served and protected by Content-Security-Policy.';
    showPacket('David: Clean HIT', 'packet-type-clean', 'pos-client');
    elNodeClient.classList.remove('active-poison');
    elNodeClient.classList.add('active-safe');
    await delay(700);

    hidePacket();
    await runPhase(4, true);
    await simulateVictimView();
    elAnimationTicker.textContent = '[PHASE 4 COMPLETE] System verified secure. Hostile inputs neutralized across all layers.';
  }

  // Play Full 5-Step Attack Sequence
  async function playFullAttackAnimation() {
    if (state.isAnimating) return;
    state.isAnimating = true;
    elBtnPlayAnimation.disabled = true;

    try {
      selectPhase(2);
      await animatePhase2();
      await delay(1200);

      selectPhase(3);
      await animatePhase3();
      await delay(1200);

      selectPhase(4);
      await animatePhase4();
    } finally {
      state.isAnimating = false;
      elBtnPlayAnimation.disabled = false;
    }
  }

  // =========================================================================
  // API CLIENT & STATUS HANDLERS
  // =========================================================================

  async function fetchStatus(isBackground = false) {
    try {
      const res = await fetch('/api/status');
      if (!res.ok) throw new Error('Status failure');
      const data = await res.json();

      updateNodeStatus(elStatusProxy, data.proxy_online);
      updateNodeStatus(elStatusUpstream, data.upstream_online);
      updateNodeStatus(elStatusAttacker, data.attacker_online);

      state.mode = data.mode;
      const isHardened = data.mode === 'hardened';
      elModeBadge.classList.toggle('hardened', isHardened);
      elModeBadge.querySelector('.mode-text').textContent = isHardened ? 'Mode: Hardened' : 'Mode: Vulnerable';
      elUpstreamModeTag.textContent = isHardened ? 'Hardened: Canonical Host' : 'Vulnerable: Dynamic Host';
      elUpstreamModeTag.classList.toggle('unkeyed-tag', !isHardened);

      if (data.cache_stats) {
        elMetricHits.textContent = data.cache_stats.hits ?? 0;
        elMetricMisses.textContent = data.cache_stats.misses ?? 0;
        elMetricKeys.textContent = data.cache_stats.active_entries ?? 0;
      }
    } catch (err) {
      if (!isBackground) {
        console.error('Status fetch error:', err);
      }
    }
  }

  function updateNodeStatus(element, isOnline) {
    const indicator = element.querySelector('.status-indicator');
    if (indicator) {
      indicator.classList.toggle('offline', !isOnline);
    }
  }

  async function toggleHardeningMode() {
    try {
      const newMode = state.mode === 'vulnerable' ? 'hardened' : 'vulnerable';
      const res = await fetch('/api/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: newMode }),
      });
      await res.json();
      await fetchStatus();
      await fetchCacheEntries();
      await simulateVictimView();
    } catch (err) {
      alert('Mode toggle failed: ' + err.message);
    }
  }

  async function purgeCache() {
    try {
      const res = await fetch('/api/cache/purge', { method: 'POST' });
      await res.json();
      await fetchStatus();
      await fetchCacheEntries();
      await simulateVictimView();
    } catch (err) {
      alert('Purge failed: ' + err.message);
    }
  }

  // Run Phase Direct
  async function runPhase(phaseNum, silent = false) {
    if (!silent) {
      elBtnRunCurrentPhase.disabled = true;
      elBtnRunCurrentPhase.querySelector('span').textContent = 'Executing...';
    }

    try {
      const res = await fetch(`/api/phase/${phaseNum}`, { method: 'POST' });
      const data = await res.json();

      if (data.transactions) {
        data.transactions.forEach((tx) => appendLogEntry(tx));
      }

      await fetchStatus();
      await fetchCacheEntries();
      await simulateVictimView();
    } catch (err) {
      appendLogEntry({
        actor: 'Simulation Engine',
        cache_status: 'ERROR',
        cache_key: 'N/A',
        verdict: 'Execution failed: ' + err.message,
        verdict_type: 'poisoned',
      });
    } finally {
      if (!silent) {
        elBtnRunCurrentPhase.disabled = false;
        elBtnRunCurrentPhase.querySelector('span').textContent = 'Execute Selected Phase';
      }
    }
  }

  async function runAllPhases() {
    elBtnRunAll.disabled = true;
    elBtnRunAll.querySelector('span').textContent = 'Executing 4 Phases...';

    try {
      const res = await fetch('/api/run-all', { method: 'POST' });
      const data = await res.json();

      if (data.transactions) {
        data.transactions.forEach((tx) => appendLogEntry(tx));
      }

      await fetchStatus();
      await fetchCacheEntries();
      await simulateVictimView();
      elAnimationTicker.textContent = 'All 4 phases completed. Hardened mode active and verified safe.';
    } catch (err) {
      alert('Execution failure: ' + err.message);
    } finally {
      elBtnRunAll.disabled = false;
      elBtnRunAll.querySelector('span').textContent = 'Execute All Phases';
    }
  }

  // Render Log
  function appendLogEntry(tx) {
    const emptyState = elTelemetryLog.querySelector('.log-empty-state');
    if (emptyState) {
      emptyState.remove();
    }

    const entry = document.createElement('div');
    const isPoisoned = tx.verdict_type === 'poisoned' || (tx.script_source && tx.script_source.includes('8882'));
    const isBlocked = tx.verdict_type === 'blocked';
    const isSafe = !isPoisoned && !isBlocked;

    entry.className = `log-entry ${isPoisoned ? 'poisoned' : isBlocked ? 'blocked' : 'safe'}`;

    const cacheBadgeClass = tx.cache_status === 'HIT' ? 'badge-hit' : 'badge-miss';

    entry.innerHTML = `
      <div class="log-entry-header">
        <span class="log-actor">${escapeHtml(tx.actor || 'Client')}</span>
        <span class="log-cache-badge ${cacheBadgeClass}">${escapeHtml(tx.cache_status || 'STATUS')}</span>
      </div>
      <div class="log-details-grid">
        <div><strong>Request:</strong> ${escapeHtml(tx.method || 'GET')} ${escapeHtml(tx.url || '/')}</div>
        <div><strong>Key:</strong> ${escapeHtml(tx.cache_key || 'N/A')}</div>
        <div><strong>Script:</strong> ${escapeHtml(tx.script_source || 'N/A')}</div>
        <div><strong>Status:</strong> ${escapeHtml(String(tx.status_code || '200'))} OK</div>
      </div>
      <div class="log-verdict ${isPoisoned ? 'poisoned' : isBlocked ? 'blocked' : 'safe'}">
        ${escapeHtml(tx.verdict || '')}
      </div>
    `;

    elTelemetryLog.prepend(entry);
  }

  // Presets
  function applyPreset(presetType) {
    if (presetType === 'clean') {
      elReqMethod.value = 'GET';
      elReqPath.value = '/';
      elReqHeaders.value = '';
    } else if (presetType === 'poison') {
      elReqMethod.value = 'GET';
      elReqPath.value = '/';
      elReqHeaders.value = 'X-Forwarded-Host: 127.0.0.1:8882';
    } else if (presetType === 'cachebuster') {
      elReqMethod.value = 'GET';
      const randCb = Math.floor(Math.random() * 90000) + 10000;
      elReqPath.value = `/?cb=${randCb}`;
      elReqHeaders.value = 'X-Forwarded-Host: 127.0.0.1:8882';
    }
  }

  // Workbench Probe Submit
  async function handleWorkbenchSubmit(e) {
    e.preventDefault();

    const method = elReqMethod.value;
    const path = elReqPath.value.trim() || '/';
    const rawHeaders = elReqHeaders.value.trim();

    const parsedHeaders = {};
    if (rawHeaders) {
      rawHeaders.split('\n').forEach((line) => {
        const idx = line.indexOf(':');
        if (idx > -1) {
          const k = line.slice(0, idx).trim();
          const v = line.slice(idx + 1).trim();
          if (k) parsedHeaders[k] = v;
        }
      });
    }

    const startTime = performance.now();
    elProbeVerdictBox.className = 'security-verdict';
    elProbeVerdictText.textContent = 'Dispatching probe to Edge Proxy (:8880)...';

    // Animate flow arrow
    elArrowClientProxy.classList.add('flow-active');

    try {
      const res = await fetch('/api/custom-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method, path, headers: parsedHeaders }),
      });
      const data = await res.json();
      const duration = Math.round(performance.now() - startTime);

      elProbeResStatus.textContent = `${data.status_code} OK`;
      elProbeResTime.textContent = `${duration} ms`;
      elProbeResKey.textContent = data.cache_key || 'N/A';
      elProbeResScript.textContent = data.script_source || 'N/A';

      const isHit = data.cache_status === 'HIT';
      elProbeBadgeCache.className = `badge ${isHit ? 'badge-hit' : 'badge-miss'}`;
      elProbeBadgeCache.textContent = `Cache: ${data.cache_status || 'MISS'}`;

      const isPoisoned = data.is_poisoned;
      const isCspActive = data.csp_present;

      if (isPoisoned) {
        elProbeVerdictBox.className = 'security-verdict poisoned';
        elProbeVerdictText.textContent = 'CRITICAL: Edge cache stored or served poisoned HTML pointing to attacker origin (:8882).';
        elNodeProxy.classList.add('active-poison');
      } else if (isCspActive) {
        elProbeVerdictBox.className = 'security-verdict blocked';
        elProbeVerdictText.textContent = 'PROTECTED: Canonical script origin enforced and guarded by Content-Security-Policy.';
        elNodeProxy.classList.add('active-safe');
      } else {
        elProbeVerdictBox.className = 'security-verdict safe';
        elProbeVerdictText.textContent = 'SAFE: Response references authentic corporate application assets.';
        elNodeProxy.classList.add('active-safe');
      }

      let rawText = `HTTP/1.1 ${data.status_code} OK\n`;
      if (data.response_headers) {
        Object.entries(data.response_headers).forEach(([k, v]) => {
          rawText += `${k}: ${v}\n`;
        });
      }
      if (data.body_snippet) {
        rawText += `\n--- Response Body Snippet ---\n${data.body_snippet}`;
      }
      elProbeRawHeaders.textContent = rawText;

      await fetchStatus();
      await fetchCacheEntries();
      await simulateVictimView();
    } catch (err) {
      elProbeVerdictBox.className = 'security-verdict poisoned';
      elProbeVerdictText.textContent = 'Request error: ' + err.message;
    } finally {
      setTimeout(() => {
        elArrowClientProxy.classList.remove('flow-active');
      }, 1000);
    }
  }

  // Cache Table
  async function fetchCacheEntries(isBackground = false) {
    try {
      const res = await fetch('/api/cache/entries');
      if (!res.ok) throw new Error('Cache entries error');
      const data = await res.json();

      elCacheTableBody.innerHTML = '';

      if (!data.entries || data.entries.length === 0) {
        elCacheTableBody.innerHTML = '<tr><td colspan="5" class="table-empty">Cache is currently empty. Dispatch requests to populate entries.</td></tr>';
        return;
      }

      data.entries.forEach((item) => {
        const row = document.createElement('tr');
        const isPoisoned = item.is_poisoned;

        row.innerHTML = `
          <td class="font-mono">${escapeHtml(item.key)}</td>
          <td>${item.age}s</td>
          <td>${item.ttl}s</td>
          <td>${item.size} B</td>
          <td>
            <span class="badge ${isPoisoned ? 'badge-miss' : 'badge-hit'}">
              ${isPoisoned ? 'POISONED' : 'CLEAN'}
            </span>
          </td>
        `;
        elCacheTableBody.appendChild(row);
      });
    } catch (err) {
      if (!isBackground) {
        console.error('Failed to fetch cache entries:', err);
      }
    }
  }

  // Simulate Victim View
  async function simulateVictimView() {
    try {
      const res = await fetch('/api/simulate-victim');
      const data = await res.json();

      const scriptSrc = data.script_source || '';
      elClientScriptVal.textContent = scriptSrc || 'None detected';

      const existingAlert = elBrowserContentArea.querySelector('.browser-alert-banner');
      if (existingAlert) {
        existingAlert.remove();
      }

      if (scriptSrc.includes('8882') || data.is_poisoned) {
        const alertBanner = document.createElement('div');
        alertBanner.className = 'browser-alert-banner';
        alertBanner.textContent = 'CRITICAL ALERT: Page rendered using poisoned cache resource from http://127.0.0.1:8882';
        elBrowserContentArea.prepend(alertBanner);
        elClientScriptVal.style.color = '#dc2626';
      } else {
        elClientScriptVal.style.color = '#2563eb';
      }
    } catch (err) {
      console.error('Victim view error:', err);
    }
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
});
