/* Mission Control Dashboard */

const API = '{{API_URL}}';
const WS_URL = (location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + location.host + '/v1/ws';

let ws = null;
let events = [];
let currentFilter = 'all';
let totalEvals = 0;
let totalBlocked = 0;
let totalAlerts = 0;
let activityData = []; // rolling window for sparkline

// ─── Tab navigation ─────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab.dataset.view));
});

function switchTab(view) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelector(`.tab[data-view="${view}"]`).classList.add('active');
    document.getElementById('view-' + view).classList.add('active');
    if (view === 'stats') loadStats();
    if (view === 'sessions') loadSessions();
}

// Keyboard shortcuts: Ctrl+1..5
document.addEventListener('keydown', e => {
    if (e.ctrlKey && e.key >= '1' && e.key <= '5') {
        e.preventDefault();
        const tabs = ['live', 'sessions', 'stats', 'audit', 'test'];
        switchTab(tabs[parseInt(e.key) - 1]);
    }
});

// ─── WebSocket ───────────────────────────────────────────
function connectWS() {
    const status = document.getElementById('ws-status');
    try {
        ws = new WebSocket(WS_URL);
    } catch (e) {
        setWSStatus(false);
        setTimeout(connectWS, 3000);
        return;
    }

    ws.onopen = () => setWSStatus(true);
    ws.onclose = () => { setWSStatus(false); setTimeout(connectWS, 3000); };
    ws.onerror = () => setWSStatus(false);

    ws.onmessage = (e) => {
        try {
            const event = JSON.parse(e.data);
            handleEvent(event);
        } catch (err) {
            console.error('Bad WS message:', err);
        }
    };
}

function setWSStatus(connected) {
    const el = document.getElementById('ws-status');
    el.className = connected ? 'ws-connected' : 'ws-disconnected';
    el.querySelector('.ws-text').textContent = connected ? 'connected' : 'disconnected';
}

// ─── Event handling ──────────────────────────────────────
function handleEvent(event) {
    events.unshift(event);
    if (events.length > 500) events.pop();

    // Update counters
    if (event.type === 'step') {
        totalEvals++;
        activityData.push({ t: Date.now(), alert: event.alert_level || 0 });
        if (activityData.length > 100) activityData.shift();
    }
    if (event.type === 'block') {
        totalEvals++;
        totalBlocked++;
    }
    if (event.type === 'alert') totalAlerts++;

    updateCounters();
    renderEvent(event);
    drawSparkline();
}

function updateCounters() {
    document.querySelector('#counter-total .counter-value').textContent = totalEvals;
    document.querySelector('#counter-blocked .counter-value').textContent = totalBlocked;
    document.querySelector('#counter-alert .counter-value').textContent = totalAlerts;
}

function renderEvent(event) {
    const feed = document.getElementById('live-feed');

    // Filter check
    if (currentFilter !== 'all') {
        if (currentFilter === 'pass' && event.type !== 'step') return;
        if (currentFilter === 'pass' && event.verdict && event.verdict !== 'PASS') return;
        if (currentFilter === 'block' && event.type !== 'block') return;
        if (currentFilter === 'alert' && event.type !== 'alert') return;
    }

    const el = document.createElement('div');

    let typeClass = event.type;
    if (event.type === 'step') typeClass = (event.verdict || 'pass').toLowerCase();
    if (event.type === 'block') typeClass = 'block';
    if (event.type === 'alert') typeClass = 'alert';
    if (event.type === 'session_start') typeClass = 'session-start';

    el.className = 'event ' + typeClass;

    const typeLabel = event.type === 'step' ? (event.verdict || 'PASS') : event.type.toUpperCase().replace('_', ' ');

    let detail = '';
    let alertBar = '';
    if (event.type === 'step') {
        const al = event.alert_level || 0;
        const barColor = al >= 0.8 ? 'var(--block)' : al >= 0.3 ? 'var(--monitor)' : 'var(--pass)';
        const barWidth = Math.max(2, Math.round(al * 60));
        alertBar = `<span class="alert-bar" style="width:${barWidth}px;background:${barColor}"></span>`;
        detail = `Step ${event.step}${alertBar} <span style="color:var(--text-dim)">alert: ${al.toFixed(2)}</span>`;
    } else if (event.type === 'block') {
        detail = `<span class="event-content">Blocked: ${escHtml(event.rule || 'unknown')}</span>`;
    } else if (event.type === 'alert') {
        detail = `<span class="event-content">Alert level: ${(event.alert_level || 0).toFixed(2)}</span>`;
    } else if (event.type === 'session_start') {
        detail = `<span style="color:var(--accent)">Session started</span>`;
    }

    const now = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

    el.innerHTML = `
        <span class="event-type ${typeClass}">${typeLabel}</span>
        <span class="event-detail">${detail}</span>
        <span class="event-session">${event.session_id || ''}</span>
        <span class="event-time">${now}</span>
    `;

    feed.prepend(el);

    // Trim feed
    while (feed.children.length > 200) feed.removeChild(feed.lastChild);

    document.getElementById('event-count').textContent = events.length + ' events';

    // Auto-scroll
    if (document.getElementById('auto-scroll').checked) {
        feed.scrollTop = 0;
    }
}

function escHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

// ─── Filters ─────────────────────────────────────────────
document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentFilter = btn.dataset.filter;
        rerenderFeed();
    });
});

function rerenderFeed() {
    const feed = document.getElementById('live-feed');
    feed.innerHTML = '';
    const filtered = events.slice().reverse();
    for (const ev of filtered) {
        renderEvent(ev);
    }
}

// ─── Clear ───────────────────────────────────────────────
document.getElementById('clear-feed').addEventListener('click', () => {
    events = [];
    document.getElementById('live-feed').innerHTML = '';
    document.getElementById('event-count').textContent = '0 events';
});

// ─── Sparkline ───────────────────────────────────────────
function drawSparkline() {
    const canvas = document.getElementById('activity-canvas');
    if (!canvas || !canvas.getContext) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;

    ctx.clearRect(0, 0, w, h);

    if (activityData.length < 2) {
        ctx.fillStyle = '#3d4f63';
        ctx.font = '12px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('Waiting for data...', w / 2, h / 2);
        return;
    }

    // Draw grid
    ctx.strokeStyle = 'rgba(30,42,58,0.5)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const y = (h / 4) * i;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
    }

    // Labels
    ctx.fillStyle = '#3d4f63';
    ctx.font = '10px monospace';
    ctx.textAlign = 'right';
    ctx.fillText('1.0', w - 4, 12);
    ctx.fillText('0.5', w - 4, h / 2 + 4);
    ctx.fillText('0.0', w - 4, h - 4);

    // Draw area
    const data = activityData;
    const step = (w - 40) / Math.max(data.length - 1, 1);

    ctx.beginPath();
    ctx.moveTo(0, h);
    for (let i = 0; i < data.length; i++) {
        const x = i * step;
        const y = h - data[i].alert * h;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    }
    ctx.lineTo((data.length - 1) * step, h);
    ctx.lineTo(0, h);
    ctx.fillStyle = 'rgba(79, 163, 224, 0.08)';
    ctx.fill();

    // Draw line
    ctx.beginPath();
    for (let i = 0; i < data.length; i++) {
        const x = i * step;
        const y = h - data[i].alert * h;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = 'var(--accent)';
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Highlight latest point
    if (data.length > 0) {
        const last = data[data.length - 1];
        const x = (data.length - 1) * step;
        const y = h - last.alert * h;
        ctx.beginPath();
        ctx.arc(x, y, 3, 0, Math.PI * 2);
        const col = last.alert >= 0.8 ? '#e05545' : last.alert >= 0.3 ? '#c09020' : '#2ea043';
        ctx.fillStyle = col;
        ctx.fill();
    }
}

// ─── Stats ───────────────────────────────────────────────
async function loadStats() {
    try {
        const resp = await fetch(API + '/v1/stats');
        const data = await resp.json();
        document.getElementById('stat-sessions').textContent = data.total_sessions || 0;
        document.getElementById('stat-steps').textContent = data.total_steps || 0;
        document.getElementById('stat-blocked').textContent = data.blocked_count || 0;

        const maxAlert = data.max_alert_level || 0;
        const alertEl = document.getElementById('stat-max-alert');
        alertEl.textContent = maxAlert.toFixed(2);
        alertEl.style.color = maxAlert >= 0.8 ? 'var(--block)' : maxAlert >= 0.3 ? 'var(--monitor)' : 'var(--pass)';

        // Verdict chart
        const bars = document.getElementById('verdict-bars');
        const dist = data.verdict_distribution || {};
        const total = Object.values(dist).reduce((a, b) => a + b, 0) || 1;
        const colors = { PASS: 'var(--pass)', MONITOR: 'var(--monitor)', FLAG: 'var(--flag)', ALERT: 'var(--block)', BLOCKED: 'var(--block)' };
        const order = ['PASS', 'MONITOR', 'FLAG', 'ALERT', 'BLOCKED'];

        bars.innerHTML = '';
        if (Object.keys(dist).length === 0) {
            bars.innerHTML = '<p class="muted">No verdict data yet</p>';
            return;
        }

        for (const verdict of order) {
            const count = dist[verdict];
            if (!count) continue;
            const pct = (count / total * 100);
            bars.innerHTML += `
                <div class="verdict-bar">
                    <span class="verdict-label" style="color:${colors[verdict] || 'var(--text)'}">${verdict}</span>
                    <div class="verdict-fill-track">
                        <div class="verdict-fill" style="width:${pct}%;background:${colors[verdict] || 'var(--accent)'}"></div>
                    </div>
                    <span class="verdict-count">${count.toLocaleString()} (${pct.toFixed(0)}%)</span>
                </div>
            `;
        }
    } catch (e) {
        console.error('Stats error:', e);
    }
}

// ─── Sessions ────────────────────────────────────────────
async function loadSessions() {
    const list = document.getElementById('session-list');
    const detail = document.getElementById('session-detail');
    detail.style.display = 'none';
    list.style.display = 'block';

    // Try to get session data from storage
    try {
        const resp = await fetch(API + '/v1/stats');
        const stats = await resp.json();

        if (stats.total_sessions === 0) {
            list.innerHTML = '<p class="muted">No sessions recorded yet. Evaluate some actions to get started.</p>';
            return;
        }

        list.innerHTML = `
            <div class="session-item" style="cursor:default;border-color:transparent;">
                <span class="muted">${stats.total_sessions} session(s), ${stats.total_steps} total steps, ${stats.blocked_count} blocked</span>
            </div>
            <p class="muted" style="margin-top:8px;">Individual session browsing requires the session list API endpoint. Use the Live Feed for real-time monitoring.</p>
        `;
    } catch (e) {
        list.innerHTML = '<p class="muted">Failed to load sessions.</p>';
    }
}

document.getElementById('refresh-sessions')?.addEventListener('click', loadSessions);
document.getElementById('back-to-sessions')?.addEventListener('click', () => {
    document.getElementById('session-detail').style.display = 'none';
    document.getElementById('session-list').style.display = 'block';
});

// ─── Audit ───────────────────────────────────────────────
document.getElementById('verify-chain').addEventListener('click', async () => {
    const result = document.getElementById('audit-result');
    const explorer = document.getElementById('chain-explorer');
    try {
        const resp = await fetch(API + '/v1/audit/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}),
        });
        const data = await resp.json();

        const icon = data.valid ? '✓' : '✗';
        result.innerHTML = `
            <strong>${icon} ${data.message}</strong><br>
            Chain length: ${data.chain_length} entries<br>
            Head hash: ${data.head_hash || 'none'}
        `;
        result.className = 'audit-result ' + (data.valid ? 'valid' : 'invalid');

        // Show chain entries if we have session history
        explorer.innerHTML = '';
    } catch (e) {
        result.textContent = 'Verification failed: ' + e.message;
        result.className = 'audit-result invalid';
    }
});

// ─── Test Console ────────────────────────────────────────
document.querySelectorAll('.preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.getElementById('test-tool-type').value = btn.dataset.tool;
        document.getElementById('test-content').value = btn.dataset.cmd;
    });
});

document.getElementById('test-evaluate').addEventListener('click', async () => {
    const toolType = document.getElementById('test-tool-type').value;
    const content = document.getElementById('test-content').value.trim();
    if (!content) return;

    const resultDiv = document.getElementById('test-result');
    resultDiv.className = 'test-result visible';
    resultDiv.innerHTML = '<p class="muted">Evaluating...</p>';

    try {
        const resp = await fetch(API + '/v1/evaluate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                tool_type: toolType,
                content: content,
                session_id: 'test_console',
            }),
        });
        const data = await resp.json();
        renderTestResult(data, content);
    } catch (e) {
        resultDiv.innerHTML = `<p style="color:var(--block)">Error: ${escHtml(e.message)}</p>`;
    }
});

// Ctrl+Enter to evaluate
document.getElementById('test-content').addEventListener('keydown', e => {
    if (e.ctrlKey && e.key === 'Enter') {
        e.preventDefault();
        document.getElementById('test-evaluate').click();
    }
});

function renderTestResult(data, content) {
    const div = document.getElementById('test-result');
    const allowed = data.allowed;
    const cb = data.circuit_breaker || {};
    const fr = data.flight_recorder;
    const gov = data.governance;

    let html = `
        <div class="result-header ${allowed ? 'allowed' : 'denied'}">
            ${allowed ? '✓ ALLOWED' : '✗ BLOCKED'}
            ${!allowed && cb.matched_rules?.length ? ' — ' + cb.matched_rules.map(r => r.name).join(', ') : ''}
        </div>
        <div class="result-body">
    `;

    // Circuit breaker
    html += `<div class="result-section">
        <div class="result-section-title">Circuit Breaker</div>
        <div class="result-row"><span class="result-key">Result</span><span class="result-val ${cb.allowed ? 'good' : 'bad'}">${cb.allowed ? 'PASS' : 'BLOCKED'}</span></div>
        <div class="result-row"><span class="result-key">Eval time</span><span class="result-val">${cb.evaluation_time_us || 0}μs</span></div>`;
    if (cb.matched_rules?.length) {
        for (const r of cb.matched_rules) {
            html += `<div class="result-row"><span class="result-key">Rule</span><span class="result-val bad">${escHtml(r.name)} (${r.category})</span></div>`;
            html += `<div class="result-row"><span class="result-key">Description</span><span class="result-val">${escHtml(r.description)}</span></div>`;
        }
    }
    html += `</div>`;

    // Flight recorder
    if (fr) {
        const alColor = fr.alert_level >= 0.8 ? 'bad' : fr.alert_level >= 0.3 ? 'warn' : 'good';
        html += `<div class="result-section">
            <div class="result-section-title">Flight Recorder</div>
            <div class="result-row"><span class="result-key">Step</span><span class="result-val">${fr.step}</span></div>
            <div class="result-row"><span class="result-key">Verdict</span><span class="result-val ${alColor}">${fr.verdict}</span></div>
            <div class="result-row"><span class="result-key">Alert level</span><span class="result-val ${alColor}">${fr.alert_level.toFixed(4)}</span></div>
            <div class="result-row"><span class="result-key">Context alignment</span><span class="result-val">${fr.context_alignment.toFixed(4)}</span></div>`;
        if (fr.signals) {
            for (const [k, v] of Object.entries(fr.signals)) {
                html += `<div class="result-row"><span class="result-key">Signal: ${k}</span><span class="result-val">${typeof v === 'number' ? v.toFixed(4) : v}</span></div>`;
            }
        }
        if (fr.boundary_proximities) {
            for (const [k, v] of Object.entries(fr.boundary_proximities)) {
                const proxColor = v >= 0.5 ? 'bad' : v >= 0.2 ? 'warn' : '';
                html += `<div class="result-row"><span class="result-key">Boundary: ${k}</span><span class="result-val ${proxColor}">${v.toFixed(4)}</span></div>`;
            }
        }
        html += `</div>`;
    }

    // Governance
    if (gov) {
        html += `<div class="result-section">
            <div class="result-section-title">Governance Chain</div>
            <div class="result-row"><span class="result-key">Chain step</span><span class="result-val">${gov.step}</span></div>
            <div class="result-row"><span class="result-key">Hash</span><span class="result-val" style="color:var(--accent)">${gov.hash}</span></div>
            <div class="result-row"><span class="result-key">Chain length</span><span class="result-val">${gov.chain_length}</span></div>`;
        if (gov.note) {
            html += `<div class="result-row"><span class="result-key">Note</span><span class="result-val bad">${escHtml(gov.note)}</span></div>`;
        }
        html += `</div>`;
    }

    html += `</div>`;
    div.innerHTML = html;
}

// ─── Init ────────────────────────────────────────────────
connectWS();
drawSparkline();
