let currentTargetIp = null;

document.getElementById('searchIpBtn').addEventListener('click', async () => {
    const ip = document.getElementById('targetIpInput').value.trim();
    if (!ip) return alert('Please enter a valid target IP address.');

    try {
        const res = await fetch('/api/target/search', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ ip_address: ip })
        });
        
        const data = await res.json();
        if (data.status === 'success') {
            // Set active target IP
            currentTargetIp = data.ip;
            document.getElementById('activeUsersCount').innerText = data.active_users;
            
            // Enable button & update states
            const btn = document.getElementById('startMonBtn');
            btn.disabled = false;
            updateStartButtonUI(data.is_monitoring);
            
            // Immediately clear current UI view and fetch logs for newly selected IP
            clearRealtimeTable();
            fetchRealtimeAlerts();
            
            alert(`Target IP ${data.ip} loaded into monitor.`);
        }
    } catch (err) {
        console.error("Error setting active target IP:", err);
        alert("Failed to connect to backend server.");
    }
});

document.getElementById('startMonBtn').addEventListener('click', async () => {
    if (!currentTargetIp) return;
    try {
        const res = await fetch('/api/target/toggle', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ ip_address: currentTargetIp })
        });
        const data = await res.json();
        if (data.status === 'success') {
            updateStartButtonUI(data.is_monitoring);
        }
    } catch (err) {
        console.error("Error toggling monitoring:", err);
    }
});

function updateStartButtonUI(isMonitoring) {
    const btn = document.getElementById('startMonBtn');
    if (isMonitoring) {
        btn.innerText = 'Stop Monitor';
        btn.className = 'btn btn-danger w-100 fw-bold';
    } else {
        btn.innerText = 'Start Monitor';
        btn.className = 'btn btn-success w-100 fw-bold';
    }
}

function clearRealtimeTable() {
    const tbody = document.getElementById('realtimeTableBody');
    if (tbody) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">Awaiting activity for selected target IP...</td></tr>';
    }
}

async function fetchRealtimeAlerts() {
    if (!currentTargetIp) return;
    
    try {
        const res = await fetch(`/api/alerts/realtime?target_ip=${encodeURIComponent(currentTargetIp)}`);
        const alerts = await res.json();
        const tbody = document.getElementById('realtimeTableBody');
        
        if (!tbody) return;
        tbody.innerHTML = '';
        
        if (alerts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">Monitoring target [${currentTargetIp}] - No active threats detected.</td></tr>`;
            return;
        }

        alerts.forEach(a => {
            const badgeClass = a.severity === 'High' ? 'bg-danger' : (a.severity === 'Medium' ? 'bg-warning text-dark' : 'bg-info text-dark');
            tbody.innerHTML += `
                <tr>
                    <td>${a.timestamp}</td>
                    <td><span class="badge bg-secondary">${a.src_ip}</span></td>
                    <td><span class="badge bg-dark">${a.dst_ip}</span></td>
                    <td>${a.alert_type}</td>
                    <td><span class="badge ${badgeClass}">${a.severity}</span></td>
                </tr>
            `;
        });
    } catch (err) {
        console.error("Realtime fetch error:", err);
    }
}

// Refresh active monitoring stream every 3 seconds
setInterval(fetchRealtimeAlerts, 3000);
