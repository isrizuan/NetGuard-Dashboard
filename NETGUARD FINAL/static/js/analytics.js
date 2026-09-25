let severityChart = null;

async function loadAnalytics() {
    try {
        const res = await fetch('/api/analytics/data');
        const data = await res.json();

        document.getElementById('totalAlertsCount').innerText = data.total_alerts;

        // Render Table Data
        const tbody = document.getElementById('analyticsTableBody');
        tbody.innerHTML = '';

        if (data.alerts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No historical data recorded in database.</td></tr>';
        } else {
            data.alerts.forEach(a => {
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
        }

        // Render Severity Chart
        const ctx = document.getElementById('severityChart').getContext('2d');
        if (severityChart) severityChart.destroy();

        severityChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['High', 'Medium', 'Low'],
                datasets: [{
                    label: 'Threat Count',
                    data: [
                        data.severity_distribution.High || 0,
                        data.severity_distribution.Medium || 0,
                        data.severity_distribution.Low || 0
                    ],
                    backgroundColor: ['#dc3545', '#ffc107', '#0dcaf0']
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: { y: { beginAtZero: true } }
            }
        });

    } catch (err) {
        console.error("Failed to load analytics data:", err);
    }
}

document.getElementById('resetAnalyticsBtn').addEventListener('click', async () => {
    if (!confirm('Are you sure you want to clear all historical analytics data?')) return;
    try {
        const res = await fetch('/api/analytics/reset', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'success') {
            loadAnalytics();
            alert('Analytics database reset successfully.');
        }
    } catch (err) {
        alert('Failed to reset analytics.');
    }
});

loadAnalytics();
