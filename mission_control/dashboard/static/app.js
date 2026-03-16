/* Mission Control Dashboard — Vanilla JS */

const API_URL = '{{API_URL}}';
const WS_URL = API_URL.replace(/^http/, 'ws') + '/v1/ws';

let ws = null;
let eventCount = 0;

// --- Tab navigation ---
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById('view-' + tab.dataset.view).classList.add('active');

        if (tab.dataset.view === 'stats') loadStats();
        if (tab.dataset.view === 'sessions') loadSessions();
    });
});

// --- WebSocket ---
function connectWS() {
    const status = document.getElementById('ws-status');
    try {
        ws = new WebSocket(WS_URL);
    } catch (e) {
        status.textContent = 'disconnected';
        status.className = 'ws-disconnected';
        setTimeout(connectWS, 3000);
        return;
    }

    ws.onopen = () => {
        status.textContent = 'connected';
        status.className = 'ws-connected';
    };

    ws.onclose = () => {
        status.textContent = 'disconnected';
        status.className = 'ws-disconnected';
        setTimeout(connectWS, 3000);
    };

    ws.onerror = () => {
        status.textContent = 'disconnected';
        status.className = 'ws-disconnected';
    };

    ws.onmessage = (e) => {
        try {
            const event = JSON.parse(e.data);
            addEvent(event);
        } catch (err) {
            console.error('Bad WS message:', err);
        }
    };
}

function addEvent(event) {
    const feed = document.getElementById('live-feed');
    const el = document.createElement('div');

    let typeClass = event.type;
    if (event.verdict) typeClass = event.verdict.toLowerCase();
    if (event.type === 'block') typeClass = 'block';
    if (event.type === 'alert') typeClass = 'alert';
    if (event.type === 'session_start') typeClass = 'session-start';

    el.className = 'event ' + typeClass;

    const typeLabel = event.type === 'step' ? (event.verdict || 'STEP') : event.type.toUpperCase();

    let detail = '';
    if (event.type === 'step') {
        detail = `Step ${event.step} — alert: ${(event.alert_level || 0).toFixed(2)}`;
    } else if (event.type === 'block') {
        detail = `Blocked by rule: ${event.rule || 'unknown'}`;
    } else if (event.type === 'alert') {
        detail = `Alert level: ${(event.alert_level || 0).toFixed(2)}`;
    } else if (event.type === 'session_start') {
        detail = `Session started`;
    }

    const now = new Date().toLocaleTimeString();

    el.innerHTML = `
        <span class="event-type ${typeClass}">${typeLabel}</span>
        <span class="event-detail">${detail}</span>
        <span class="event-session">${event.session_id || ''}</span>
        <span class="event-time">${now}</span>
    `;

    feed.prepend(el);
    eventCount++;
    document.getElementById('event-count').textContent = eventCount + ' events';
}

// --- Clear feed ---
document.getElementById('clear-feed').addEventListener('click', () => {
    document.getElementById('live-feed').innerHTML = '';
    eventCount = 0;
    document.getElementById('event-count').textContent = '0 events';
});

// --- Stats ---
async function loadStats() {
    try {
        const resp = await fetch(API_URL + '/v1/stats');
        const data = await resp.json();
        document.getElementById('stat-sessions').textContent = data.total_sessions;
        document.getElementById('stat-steps').textContent = data.total_steps;
        document.getElementById('stat-blocked').textContent = data.blocked_count;
        document.getElementById('stat-max-alert').textContent = (data.max_alert_level || 0).toFixed(2);

        // Verdict chart
        const chart = document.getElementById('verdict-chart');
        const dist = data.verdict_distribution || {};
        const total = Object.values(dist).reduce((a, b) => a + b, 0) || 1;

        chart.innerHTML = '<h3 style="margin-bottom:16px;font-size:14px;">Verdict Distribution</h3>';
        const colors = { PASS: 'var(--pass)', MONITOR: 'var(--monitor)', ALERT: 'var(--alert)', BLOCKED: 'var(--block)' };
        for (const [verdict, count] of Object.entries(dist)) {
            const pct = (count / total * 100).toFixed(0);
            chart.innerHTML += `
                <div class="verdict-bar">
                    <span class="verdict-label">${verdict}</span>
                    <div class="verdict-fill" style="width:${pct}%;background:${colors[verdict] || 'var(--accent)'}"></div>
                    <span class="verdict-count">${count} (${pct}%)</span>
                </div>
            `;
        }
        if (Object.keys(dist).length === 0) {
            chart.innerHTML += '<p class="muted">No verdict data yet</p>';
        }
    } catch (e) {
        console.error('Failed to load stats:', e);
    }
}

// --- Sessions ---
async function loadSessions() {
    // Use stats endpoint as a proxy; individual session data from history endpoint
    const list = document.getElementById('session-list');
    list.innerHTML = '<p class="muted">Session list requires storage backend. Use the Live Feed for real-time monitoring.</p>';
}

// --- Audit ---
document.getElementById('verify-chain').addEventListener('click', async () => {
    const result = document.getElementById('audit-result');
    try {
        const resp = await fetch(API_URL + '/v1/audit/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}),
        });
        const data = await resp.json();
        result.textContent = `${data.message} — Chain length: ${data.chain_length}, Hash: ${data.head_hash}`;
        result.className = 'audit-result ' + (data.valid ? 'valid' : 'invalid');
    } catch (e) {
        result.textContent = 'Failed to verify: ' + e.message;
        result.className = 'audit-result invalid';
    }
});

// --- Init ---
connectWS();
