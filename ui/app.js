/**
 * Web Cache Poisoning Laboratory Client Application
 * Handles API communication, scenario stepping, interactive probes,
 * and live cache telemetry visualization.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Application State
  const state = {
    currentPhase: 1,
    mode: 'vulnerable',
    autoRefreshInterval: null,
  };

  // DOM Elements
  const elStatusProxy = document.getElementById('status-proxy');
  const elStatusUpstream = document.getElementById('status-upstream');
  const elStatusAttacker = document.getElementById('status-attacker');
  const elModeBadge = document.getElementById('mode-badge');
  const elBtnToggleMode = document.getElementById('btn-toggle-mode');
  const elBtnPurgeCache = document.getElementById('btn-purge-cache');
  const elUpstreamModeTag = document.getElementById('upstream-mode-tag');

  const elMetricHits = document.getElementById('metric-hits');
  const elMetricMisses = document.getElementById('metric-misses');
  const elMetricKeys = document.getElementById('metric-keys');

  const elPhaseButtons = document.querySelectorAll('.btn-phase');
  const elPhaseContextTitle = document.getElementById('phase-context-title');
  const elPhaseContextDesc = document.getElementById('phase-context-desc');
  const elBtnRunCurrentPhase = document.getElementById('btn-run-current-phase');
  const elBtnRunAll = document.getElementById('btn-run-all');
  const elTelemetryLog = document.getElementById('telemetry-log-container');
  const elBtnClearLogs = document.getElementById('btn-clear-logs');

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

  const elCacheTableBody = document.getElementById('cache-table-body');
  const elBtnRefreshCache = document.getElementById('btn-refresh-cache');
  const elBtnRefreshView = document.getElementById('btn-refresh-view');
  const elBrowserContentArea = document.getElementById('browser-content-area');
  const elClientScriptVal = document.getElementById('client-script-val');

  // Phase Metadata Dictionary
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

  // Initial Load
  init();

  function init() {
    setupEventListeners();
    fetchStatus();
    fetchCacheEntries();
    simulateVictimView();

    // Periodic telemetry polling every 4 seconds
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

    // Phase selector tabs
    elPhaseButtons.forEach((btn) => {
      btn.addEventListener('click', () => {
        const p = parseInt(btn.dataset.phase, 10);
        selectPhase(p);
      });
    });

    // Run current phase
    elBtnRunCurrentPhase.addEventListener('click', () => {
      runPhase(state.currentPhase);
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
  }

  // API: Fetch Cluster & Cache Status
  async function fetchStatus(isBackground = false) {
    try {
      const res = await fetch('/api/status');
      if (!res.ok) throw new Error('Status endpoint failure');
      const data = await res.json();

      // Update Node Indicators
      updateNodeStatus(elStatusProxy, data.proxy_online);
      updateNodeStatus(elStatusUpstream, data.upstream_online);
      updateNodeStatus(elStatusAttacker, data.attacker_online);

      // Update Mode Badge
      state.mode = data.mode;
      const isHardened = data.mode === 'hardened';
      elModeBadge.classList.toggle('hardened', isHardened);
      elModeBadge.querySelector('.mode-text').textContent = isHardened ? 'Mode: Hardened' : 'Mode: Vulnerable';
      elUpstreamModeTag.textContent = isHardened ? 'Hardened: Canonical Host' : 'Vulnerable: Dynamic Host';
      elUpstreamModeTag.classList.toggle('unkeyed-tag', !isHardened);

      // Update Metrics
      if (data.cache_stats) {
        elMetricHits.textContent = data.cache_stats.hits ?? 0;
        elMetricMisses.textContent = data.cache_stats.misses ?? 0;
        elMetricKeys.textContent = data.cache_stats.active_entries ?? 0;
      }
    } catch (err) {
      if (!isBackground) {
        console.error('Failed to fetch status:', err);
      }
    }
  }

  function updateNodeStatus(element, isOnline) {
    const indicator = element.querySelector('.status-indicator');
    if (indicator) {
      indicator.classList.toggle('offline', !isOnline);
    }
  }

  // API: Toggle Hardening Mode
  async function toggleHardeningMode() {
    try {
      const newMode = state.mode === 'vulnerable' ? 'hardened' : 'vulnerable';
      const res = await fetch('/api/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: newMode }),
      });
      const data = await res.json();
      fetchStatus();
      fetchCacheEntries();
      simulateVictimView();
    } catch (err) {
      alert('Failed to switch operational mode: ' + err.message);
    }
  }

  // API: Purge Cache
  async function purgeCache() {
    try {
      const res = await fetch('/api/cache/purge', { method: 'POST' });
      const data = await res.json();
      fetchStatus();
      fetchCacheEntries();
      simulateVictimView();
    } catch (err) {
      alert('Failed to purge cache: ' + err.message);
    }
  }

  // API: Run Single Phase
  async function runPhase(phaseNum) {
    elBtnRunCurrentPhase.disabled = true;
    elBtnRunCurrentPhase.querySelector('span').textContent = 'Executing...';

    try {
      const res = await fetch(`/api/phase/${phaseNum}`, { method: 'POST' });
      const data = await res.json();

      if (data.transactions) {
        data.transactions.forEach((tx) => appendLogEntry(tx));
      }

      fetchStatus();
      fetchCacheEntries();
      simulateVictimView();
    } catch (err) {
      appendLogEntry({
        actor: 'Simulation Engine',
        cache_status: 'ERROR',
        cache_key: 'N/A',
        verdict: 'Execution failed: ' + err.message,
        verdict_type: 'poisoned',
      });
    } finally {
      elBtnRunCurrentPhase.disabled = false;
      elBtnRunCurrentPhase.querySelector('span').textContent = 'Execute Selected Phase';
    }
  }

  // API: Run All Phases
  async function runAllPhases() {
    elBtnRunAll.disabled = true;
    elBtnRunAll.querySelector('span').textContent = 'Running All Phases...';

    try {
      const res = await fetch('/api/run-all', { method: 'POST' });
      const data = await res.json();

      if (data.transactions) {
        data.transactions.forEach((tx) => appendLogEntry(tx));
      }

      fetchStatus();
      fetchCacheEntries();
      simulateVictimView();
    } catch (err) {
      alert('Execution failure: ' + err.message);
    } finally {
      elBtnRunAll.disabled = false;
      elBtnRunAll.querySelector('span').textContent = 'Execute All Phases';
    }
  }

  // Render Telemetry Log Entry
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

  // API: Interactive Workbench Submit
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
    elProbeVerdictText.textContent = 'Dispatching probe...';

    try {
      const res = await fetch('/api/custom-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method, path, headers: parsedHeaders }),
      });
      const data = await res.json();
      const duration = Math.round(performance.now() - startTime);

      // Render Response Analysis
      elProbeResStatus.textContent = `${data.status_code} OK`;
      elProbeResTime.textContent = `${duration} ms`;
      elProbeResKey.textContent = data.cache_key || 'N/A';
      elProbeResScript.textContent = data.script_source || 'N/A';

      const isHit = data.cache_status === 'HIT';
      elProbeBadgeCache.className = `badge ${isHit ? 'badge-hit' : 'badge-miss'}`;
      elProbeBadgeCache.textContent = `Cache: ${data.cache_status || 'MISS'}`;

      // Verdict styling
      const isPoisoned = data.is_poisoned;
      const isCspActive = data.csp_present;

      if (isPoisoned) {
        elProbeVerdictBox.className = 'security-verdict poisoned';
        elProbeVerdictText.textContent = 'CRITICAL: Edge cache stored or served poisoned HTML pointing to attacker origin (:8882).';
      } else if (isCspActive) {
        elProbeVerdictBox.className = 'security-verdict blocked';
        elProbeVerdictText.textContent = 'PROTECTED: Canonical script origin enforced and guarded by Content-Security-Policy.';
      } else {
        elProbeVerdictBox.className = 'security-verdict safe';
        elProbeVerdictText.textContent = 'SAFE: Response references authentic corporate application assets.';
      }

      // Raw headers
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

      fetchStatus();
      fetchCacheEntries();
      simulateVictimView();
    } catch (err) {
      elProbeVerdictBox.className = 'security-verdict poisoned';
      elProbeVerdictText.textContent = 'Request error: ' + err.message;
    }
  }

  // API: Fetch Cache Store Entries
  async function fetchCacheEntries(isBackground = false) {
    try {
      const res = await fetch('/api/cache/entries');
      if (!res.ok) throw new Error('Cache entries failure');
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

  // API: Simulate Innocent Victim Browser View
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
        elClientScriptVal.style.color = '#0284c7';
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
