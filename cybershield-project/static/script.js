let radarChart;

// Initialize the Radar Chart
function initChart() {
    const ctx = document.getElementById('radarChart').getContext('2d');
    radarChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(20).fill(''),
            datasets: [{
                label: 'RPS',
                data: Array(20).fill(0),
                borderColor: '#0d6efd',
                backgroundColor: 'rgba(13, 110, 253, 0.1)',
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { y: { beginAtZero: true } },
            plugins: { legend: { display: false } }
        }
    });
}

async function updateDashboard() {
    try {
        const response = await fetch('/metrics');
        const data = await response.json();

        // Update Text Stats
        document.getElementById('total-req').innerText = data.totalRequests;
        document.getElementById('rps-val').innerText = data.rps.toFixed(1);

        // Update Logs Table (Original Columns)
        const logBody = document.getElementById('log-body');
        logBody.innerHTML = data.logs.map(log => `
            <tr>
                <td>${log.IP}</td>
                <td>${log.Endpoint}</td>
                <td>${log.Method}</td>
                <td><span class="badge ${log.Status === 'Allowed' ? 'bg-success' : 'bg-danger'}">${log.Status}</span></td>
                <td>${log.Reason}</td>
                <td>${log.Time}</td>
            </tr>
        `).reverse().join('');

        // Update Blacklist list
        const blacklistDiv = document.getElementById('blacklist-ips');
        blacklistDiv.innerHTML = data.config.security.blacklisted_ips.map(ip => 
            `<div class="badge bg-secondary m-1 p-2">${ip}</div>`
        ).join('');

        // Push new RPS data to chart
        radarChart.data.datasets[0].data.push(data.rps);
        radarChart.data.datasets[0].data.shift();
        radarChart.update('none');

    } catch (err) {
        console.error("Fetch Error:", err);
    }
}

async function addBlock() {
    const ip = document.getElementById('ip-input').value;
    if (!ip) return;

    await fetch('/api/blacklist', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ ip: ip })
    });
    
    document.getElementById('ip-input').value = '';
    updateDashboard();
}

window.onload = () => {
    initChart();
    setInterval(updateDashboard, 1000);
};