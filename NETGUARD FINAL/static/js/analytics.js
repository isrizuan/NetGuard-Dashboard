let chartInstance = null;

async function loadAnalytics() {
    const res = await fetch('/api/analytics/data');
    const data = await res.json();

    document.getElementById('totalAlertsCount').innerText = data.total_alerts;

    // Populate Table
    const tbody = document.getElementById('analyticsTableBody');
    tbody.innerHTML = '';
    data.alerts.forEach(a => {
        tbody.innerHTML += `
            <tr>
                <td>${a.timestamp}</td>
                <td>${a.src_ip}</td>
                <td>${a.dst_ip}</td>
                <td>${a.alert_type}</td>
                <td><span class="badge ${a.severity === 'High' ? 'bg-danger' : 'bg-info'}">${a.severity}</span></td>
            </tr>
        `;
    });

    // Render Chart
    const ctx = document.getElementById('severityChart').getContext('2d');
    if (chartInstance) chartInstance.destroy();

    chartInstance = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['High', 'Medium', 'Low'],
            datasets: [{
                data: [
                    data.severity_distribution.High,
                    data.severity_distribution.Medium,
                    data.severity_distribution.Low
                ],
                backgroundColor: ['#dc3545', '#ffc107', '#0dcaf0']
            }]
        }
    });
}

document.getElementById('resetAnalyticsBtn').addEventListener('click', async () => {
    if (!confirm('Are you sure you want to reset and clear all collected analytics data?')) return;

    const res = await fetch('/api/analytics/reset', { method: 'POST' });
    const data = await res.json();
    if (data.status === 'success') {
        alert(data.message);
        loadAnalytics();
    }
});

loadAnalytics();