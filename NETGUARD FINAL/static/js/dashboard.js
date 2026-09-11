let currentTargetIp = null;

document.getElementById('searchIpBtn').addEventListener('click', async () => {
    const ip = document.getElementById('targetIpInput').value.trim();
    if (!ip) return alert('Please enter an IP address.');

    try {
        const res = await fetch('/api/target/search', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ ip_address: ip })
        });

        if (!res.ok) {
            alert('Failed to find target IP. Check server logs.');
            return;
        }

        const data = await res.json();

        if (data.status === 'success') {
            currentTargetIp = data.ip;
            document.getElementById('activeUsersCount').innerText = data.active_users;
            const btn = document.getElementById('startMonBtn');
            btn.disabled = false;
            updateStartButtonUI(data.is_monitoring);
            alert(`Target IP ${data.ip} loaded successfully!`);
        }
    } catch (err) {
        console.error("Error fetching target IP:", err);
        alert("Could not connect to backend server.");
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
        btn.className = 'btn btn-danger w-100';
    } else {
        btn.innerText = 'Start Monitor';
        btn.className = 'btn btn-success w-100';
    }
}