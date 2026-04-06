// ═══════════════════════════════════════
//  CyberShield Dashboard — script.js
//  Features: Honey-Token, Security Level,
//            Threat Scoring, Perf Duel, Attack Detections
// ═══════════════════════════════════════

let trafficChart;
let prevHoneyHits = 0;
let prevBlocked = 0;
let legacyLatencies = [];
let cybershieldLatencies = [];
let benchSource = null;
let sqlAttempts = 0;
let xssAttempts = 0;
let rateAttempts = 0;

// ─── Chart Init ───────────────────────
function initChart() {
    const ctx = document.getElementById('trafficChart').getContext('2d');
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(30).fill(''),
            datasets: [{
                label: 'RPS',
                data: Array(30).fill(0),
                borderColor: '#2ea8d5',
                backgroundColor: 'rgba(46,168,213,0.12)',
                fill: true,
                tension: 0.35,
                pointRadius: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } },
                x: { grid: { display: false }, ticks: { display: false } }
            },
            plugins: { legend: { display: false } },
            animation: { duration: 300 }
        }
    });
}

// ─── Main Dashboard Poll ──────────────
async function updateDashboard() {
    try {
        const res = await fetch('/metrics');
        const data = await res.json();

        document.getElementById('total-req').innerText = data.totalRequests;
        document.getElementById('rps-val').innerText = (data.rps || 0).toFixed(1);
        document.getElementById('blocked-val').innerText = data.blocked || 0;
        document.getElementById('honey-val').innerText = data.honeyHits || 0;

        // Feature 1: Show honey-token alert popup if new hit
        if ((data.honeyHits || 0) > prevHoneyHits) {
            const newLogs = (data.logs || []).filter(l => l.Reason && l.Reason.includes('Honey-Token'));
            const latest = newLogs[newLogs.length - 1];
            if (latest) showHoneyAlert(latest.IP, latest.Endpoint);
            prevHoneyHits = data.honeyHits;
        }

        // Feature 1b: Show block alert popup on new blocked traffic
        if ((data.blocked || 0) > prevBlocked) {
            const blockedLogs = (data.logs || []).filter(l => l.Status === 'Blocked' || l.Status === 'BANNED');
            const latest = blockedLogs[blockedLogs.length - 1];
            if (latest) showBlockAlert(latest.Reason || 'Blocked request');
            prevBlocked = data.blocked || 0;
        }

        // Feature 2: Sync security level buttons
        syncLevelUI(data.securityLevel || 0);

        // Feature 3: Update threat scores
        updateThreatList();

        // Attack Detections
        let newSql = 0, newXss = 0, newRate = 0, newBan = 0, newWaf = 0;
        (data.logs || []).forEach(log => {
            if (log.Status === 'Blocked' || log.Status === 'BANNED') {
                const reason = log.Reason || '';
                if (reason.includes('SQL Injection')) newSql++;
                if (reason.includes('XSS')) newXss++;
                if (reason.includes('Rate Limit')) newRate++;
                if (reason.includes('BANNED') || reason.includes('Blacklisted') || log.Status === 'BANNED') newBan++;
                if (reason.includes('WAF') || reason.includes('Suspicious User-Agent') || (!reason.includes('SQL Injection') && !reason.includes('XSS') && !reason.includes('Rate Limit') && !reason.includes('BANNED') && log.Status === 'Blocked')) newWaf++;
            }
        });
        sqlAttempts = newSql;
        xssAttempts = newXss;
        rateAttempts = newRate;
        document.getElementById('ban-count').innerText = newBan;
        document.getElementById('waf-count').innerText = newWaf;
        updateAttackBars(newBan, newWaf);

        // Chart
        trafficChart.data.datasets[0].data.push(data.rps || 0);
        trafficChart.data.datasets[0].data.shift();
        trafficChart.update('none');

        // Log table
        const logBody = document.getElementById('log-body');
        const rows = (data.logs || []).slice().reverse().map(log => {
            let pillClass = 'st-ok';
            if (log.Status === 'Blocked' || log.Status === 'BANNED') pillClass = 'st-err';
            else if (log.Status === 'Monitor') pillClass = 'st-mon';
            const honey = log.Reason && log.Reason.includes('Honey-Token') ? '🪤 ' : '';
            return `<tr>
                <td><code>${log.IP}</code></td>
                <td style="font-family:monospace;font-size:11px">${log.Endpoint}</td>
                <td><span style="font-weight:700">${log.Method}</span></td>
                <td><span class="st-pill ${pillClass}">${log.Status}</span></td>
                <td>${honey}${log.Reason}</td>
                <td style="color:#94a3b8">${log.Time}</td>
            </tr>`;
        }).join('');
        logBody.innerHTML = rows;

        // Blacklist display
        const bl = document.getElementById('blacklist-ips');
        const ips = (data.config && data.config.security && data.config.security.blacklisted_ips) || [];
        bl.innerHTML = ips.length === 0
            ? '<div style="color:#94a3b8;font-size:12px;padding:4px 0">No IPs blocked</div>'
            : ips.map(ip => `<div class="ip-item"><span><span class="dot-red"></span>${ip}</span><span class="reason-tag">BLOCKED</span></div>`).join('');

    } catch (err) {
        console.error('Fetch Error:', err);
    }
}

// ─── Feature 1: Honey-Token Alert ─────
function showHoneyAlert(ip, path) {
    const el = document.getElementById('honey-alert');
    document.getElementById('honey-alert-msg').innerText = `IP: ${ip} → ${path}`;
    el.style.display = 'block';
    setTimeout(() => { el.style.display = 'none'; }, 4000);
}

function showBlockAlert(reason) {
    const el = document.getElementById('honey-alert');
    document.getElementById('honey-alert-msg').innerText = `Blocked: ${reason}`;
    el.style.display = 'block';
    setTimeout(() => { el.style.display = 'none'; }, 4000);
}

// ─── Feature 2: Security Level ────────
function setLevel(lvl) {
    fetch(`/api/set-level?level=${lvl}`)
        .then(r => r.json())
        .then(d => syncLevelUI(d.level));
}

function syncLevelUI(lvl) {
    for (let i = 0; i <= 2; i++) {
        const btn = document.getElementById(`lvl-${i}`);
        if (!btn) continue;
        btn.classList.toggle('active', i === lvl);
    }
    const body = document.getElementById('body-root');
    body.classList.remove('mode-monitor', 'mode-active', 'mode-lockdown');
    if (lvl === 0) body.classList.add('mode-monitor');
    else if (lvl === 1) body.classList.add('mode-active');
    else if (lvl === 2) body.classList.add('mode-lockdown');
}

// ─── Feature 3: Threat Heatmap ────────
async function updateThreatList() {
    try {
        const res = await fetch('/api/top-threats');
        const threats = await res.json();

        // Update top threat card
        const top = threats && threats.length > 0 ? threats[0].score : 0;
        document.getElementById('top-threat-val').innerText = top;

        const el = document.getElementById('threat-list');
        if (!threats || threats.length === 0) {
            el.innerHTML = '<div style="color:#94a3b8;font-size:12px;padding:8px 0">No threats detected</div>';
            return;
        }
        el.innerHTML = threats.map(t => {
            const pct = Math.min(t.score, 100);
            let color = '#22c97a';
            if (pct >= 40) color = '#f0a025';
            if (pct >= 70) color = '#e84060';
            const banned = pct >= 100;
            const icon = banned ? '🚫' : pct >= 70 ? '⚠️' : '👀';
            return `<div class="threat-row">
                <span class="threat-ip">${icon} <code>${t.ip}</code></span>
                <div class="threat-bar-wrap">
                    <div class="threat-bar" style="width:${pct}%;background:${color}"></div>
                </div>
                <span class="threat-score" style="color:${color}">${t.score}/100</span>
            </div>`;
        }).join('');
    } catch (e) {}
}

// ─── Attack Detections ────────────────
function updateAttackBars(banAttempts = 0, wafAttempts = 0) {
    const max = 50; // Max for bar width
    document.getElementById('sql-bar').style.width = `${Math.min(sqlAttempts / max * 100, 100)}%`;
    document.getElementById('xss-bar').style.width = `${Math.min(xssAttempts / max * 100, 100)}%`;
    document.getElementById('rate-bar').style.width = `${Math.min(rateAttempts / max * 100, 100)}%`;
    document.getElementById('ban-bar').style.width = `${Math.min(banAttempts / max * 100, 100)}%`;
    document.getElementById('waf-bar').style.width = `${Math.min(wafAttempts / max * 100, 100)}%`;
    document.getElementById('sql-count').innerText = sqlAttempts;
    document.getElementById('xss-count').innerText = xssAttempts;
    document.getElementById('rate-count').innerText = rateAttempts;
    document.getElementById('ban-count').innerText = banAttempts;
    document.getElementById('waf-count').innerText = wafAttempts;
    document.getElementById('attack-total').innerText = `${sqlAttempts + xssAttempts + rateAttempts + banAttempts + wafAttempts} DETECTED`;
}

// ─── Feature 4: Bench SSE ─────────────
function startBenchStream() {
    if (benchSource) benchSource.close();
    benchSource = new EventSource('/api/bench-stream');
    benchSource.onmessage = function(e) {
        const m = JSON.parse(e.data);
        if (m.side === 'Legacy') {
            legacyLatencies.push(m.latency);
            if (legacyLatencies.length > 20) legacyLatencies.shift();
            const avg = Math.round(legacyLatencies.reduce((a,b)=>a+b,0)/legacyLatencies.length);
            const display = avg < 100 ? `${avg}ms fast` : `${avg}ms`;
            document.getElementById('legacy-latency').innerText = display;
        } else {
            cybershieldLatencies.push(m.latency);
            if (cybershieldLatencies.length > 20) cybershieldLatencies.shift();
            const avg = Math.round(cybershieldLatencies.reduce((a,b)=>a+b,0)/cybershieldLatencies.length);
            const display = avg < 100 ? `${avg}ms fast` : `${avg}ms`;
            document.getElementById('cybershield-latency').innerText = display;
        }
    };
    benchSource.onerror = function() {
        console.warn('Bench SSE disconnected, reconnecting...');
        setTimeout(startBenchStream, 2000);
    };
}

function setBench(mode) {
    fetch(`/api/set-benchmark?mode=${mode}`)
        .then(r => r.json())
        .then(d => {
            document.getElementById('bench-legacy').classList.toggle('active-bench', d.mode === 'Legacy');
            document.getElementById('bench-cybershield').classList.toggle('active-bench', d.mode === 'CyberShield');
        });
}

function updateAttackConsole(line) {
    const container = document.getElementById('attack-console-lines');
    const el = document.createElement('span');
    el.className = 'attack-console-line';
    el.innerText = line;
    container.appendChild(el);
    while (container.children.length > 6) {
        container.removeChild(container.firstChild);
    }
}

function showAttackConsole() {
    document.getElementById('attack-console').style.display = 'block';
    document.getElementById('attack-console-lines').innerHTML = '';
}

function hideAttackConsole() {
    setTimeout(() => {
        document.getElementById('attack-console').style.display = 'none';
    }, 2000);
}

async function launchAttack() {
    const statusEl = document.getElementById('attack-status');
    showAttackConsole();
    updateAttackConsole('Initializing backend worker...');
    statusEl.innerText = '⏳ Launching attack simulation...';
    legacyLatencies = [];
    cybershieldLatencies = [];
    if (!benchSource || benchSource.readyState === EventSource.CLOSED) {
        startBenchStream();
    }

    const attackRequests = [];
    for (let i = 0; i < 10; i++) {
        attackRequests.push({url: "/?username=admin' OR '1'='1", method: 'POST', body: "username=admin' OR '1'='1", headers: {'Content-Type': 'application/x-www-form-urlencoded'}});
        attackRequests.push({url: "/?q=<script>alert('XSS')</script>", method: 'GET'});
    }
    for (let i = 0; i < 10; i++) {
        attackRequests.push({url: '/v1/admin/config-backup', method: 'GET'});
    }
    for (let i = 0; i < 10; i++) {
        attackRequests.push({url: '/?page=attack', method: 'GET'});
    }
    // add some normal allowed requests too
    for (let i = 0; i < 10; i++) {
        attackRequests.push({url: '/?page=home', method: 'GET'});
    }

    await fetch('/api/set-benchmark?mode=Legacy');
    document.getElementById('bench-legacy').classList.add('active-bench');
    document.getElementById('bench-cybershield').classList.remove('active-bench');
    updateAttackConsole('Switched to Legacy mode');

    for (let i = 0; i < 25; i++) {
        const req = attackRequests[i];
        await sendAttackRequest(req, statusEl, i + 1);
    }

    updateAttackConsole('Switching to CyberShield mode...');
    await fetch('/api/set-benchmark?mode=CyberShield');
    document.getElementById('bench-cybershield').classList.add('active-bench');
    document.getElementById('bench-legacy').classList.remove('active-bench');

    for (let i = 25; i < 50; i++) {
        const req = attackRequests[i];
        await sendAttackRequest(req, statusEl, i + 1);
    }

    updateAttackConsole('Attack complete, collecting results...');
    statusEl.innerText = '✅ Attack complete — results updated above';
    await updateDashboard();
    setTimeout(() => {
        updateAttackConsole('Backend worker idle');
        hideAttackConsole();
    }, 2000);
}

async function sendAttackRequest(req, statusEl, count) {
    const options = { method: req.method };
    if (req.headers) options.headers = req.headers;
    if (req.body) options.body = req.body;
    await fetch(req.url, options).catch(() => {});
    statusEl.innerText = `${count <= 25 ? '🔴 Legacy' : '🚀 CyberShield'} Attack: ${count}/50 requests sent`;
    updateAttackConsole(`Dispatched request #${count}: ${req.url}`);
    await new Promise(resolve => setTimeout(resolve, 140));
}

// ─── IP Block ─────────────────────────
async function addBlock() {
    const ip = document.getElementById('ip-input').value.trim();
    if (!ip) return;
    await fetch('/api/blacklist', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ ip })
    });
    document.getElementById('ip-input').value = '';
    updateDashboard();
}

// ─── Boot ─────────────────────────────
window.onload = () => {
    initChart();
    startBenchStream();
    setInterval(updateDashboard, 1500);
    setInterval(updateThreatList, 3000);
};
