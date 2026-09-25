import os
import io
import csv
import threading
import requests
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from scapy.all import sniff, IP, TCP, UDP, ICMP

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'netguard-standalone-2026')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///netguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', 'YOUR_TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID', 'YOUR_TELEGRAM_CHAT_ID')

def send_telegram_alert(message):
    if TELEGRAM_BOT_TOKEN != "YOUR_TELEGRAM_BOT_TOKEN":
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
        try:
            requests.post(url, json=payload, timeout=5)
        except Exception as e:
            print(f"Telegram error: {e}")

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

USERS = {"admin": "admin123"}

@login_manager.user_loader
def load_user(user_id):
    if user_id in USERS:
        return User(user_id, user_id)
    return None

class TargetIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    active_users = db.Column(db.Integer, default=1)
    is_monitoring = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ThreatAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    src_ip = db.Column(db.String(45), nullable=False)
    dst_ip = db.Column(db.String(45), nullable=False)
    alert_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        with app.app_context():
            monitored_targets = [t.ip_address for t in TargetIP.query.filter_by(is_monitoring=True).all()]
            if src_ip in monitored_targets or dst_ip in monitored_targets:
                alert_type = None
                severity = "Low"

                if TCP in packet and packet[TCP].flags == 'S':
                    alert_type = "TCP Port Scan / Connection Init"
                    severity = "High"
                elif ICMP in packet:
                    alert_type = "ICMP Ping Sweep Detected"
                    severity = "Medium"
                elif UDP in packet:
                    alert_type = "UDP Traffic Probe"
                    severity = "Low"

                if alert_type:
                    alert = ThreatAlert(src_ip=src_ip, dst_ip=dst_ip, alert_type=alert_type, severity=severity)
                    db.session.add(alert)
                    db.session.commit()

                    if severity == "High":
                        send_telegram_alert(
                            f"⚠️ *HIGH THREAT DETECTED*\nSource: `{src_ip}`\nTarget: `{dst_ip}`\nType: `{alert_type}`"
                        )

def start_packet_sniffer():
    try:
        sniff(prn=packet_callback, store=0)
    except Exception as e:
        print(f"Sniffer background thread note: {e}")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in USERS and USERS[username] == password:
            user = User(username, username)
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/analytics')
@login_required
def analytics():
    return render_template('analytics.html')

@app.route('/api/target/search', methods=['POST'])
@login_required
def search_target():
    data = request.get_json()
    ip = data.get('ip_address')
    if not ip:
        return jsonify({'status': 'error', 'message': 'IP address is required'}), 400
    
    target = TargetIP.query.filter_by(ip_address=ip).first()
    if not target:
        target = TargetIP(ip_address=ip, active_users=1, is_monitoring=False)
        db.session.add(target)
    else:
        target.active_users += 1
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'ip': target.ip_address,
        'active_users': target.active_users,
        'is_monitoring': target.is_monitoring
    })

@app.route('/api/target/toggle', methods=['POST'])
@login_required
def toggle_monitoring():
    data = request.get_json()
    ip = data.get('ip_address')
    target = TargetIP.query.filter_by(ip_address=ip).first()
    if target:
        target.is_monitoring = not target.is_monitoring
        db.session.commit()
        status = "STARTED" if target.is_monitoring else "STOPPED"
        send_telegram_alert(f"🚨 *NetGuard Alert*\nMonitoring *{status}* for Target IP: `{ip}`")
        return jsonify({'status': 'success', 'is_monitoring': target.is_monitoring})
    return jsonify({'status': 'error', 'message': 'IP not found'}), 404

@app.route('/api/alerts/realtime', methods=['GET'])
@login_required
def get_realtime_alerts():
    target_ip = request.args.get('target_ip')
    if not target_ip:
        return jsonify([])

    alerts = ThreatAlert.query.filter(
        (ThreatAlert.src_ip == target_ip) | (ThreatAlert.dst_ip == target_ip)
    ).order_by(ThreatAlert.timestamp.desc()).limit(15).all()

    return jsonify([{
        'id': a.id,
        'src_ip': a.src_ip,
        'dst_ip': a.dst_ip,
        'alert_type': a.alert_type,
        'severity': a.severity,
        'timestamp': a.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    } for a in alerts])

@app.route('/api/analytics/data', methods=['GET'])
@login_required
def get_analytics_data():
    alerts = ThreatAlert.query.order_by(ThreatAlert.timestamp.desc()).all()
    severity_counts = {'High': 0, 'Medium': 0, 'Low': 0}
    target_counts = {}

    for a in alerts:
        if a.severity in severity_counts:
            severity_counts[a.severity] += 1
        target_counts[a.dst_ip] = target_counts.get(a.dst_ip, 0) + 1

    return jsonify({
        'total_alerts': len(alerts),
        'severity_distribution': severity_counts,
        'target_distribution': target_counts,
        'alerts': [{
            'id': a.id,
            'src_ip': a.src_ip,
            'dst_ip': a.dst_ip,
            'alert_type': a.alert_type,
            'severity': a.severity,
            'timestamp': a.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        } for a in alerts]
    })

@app.route('/api/analytics/export/csv', methods=['GET'])
@login_required
def export_csv():
    alerts = ThreatAlert.query.order_by(ThreatAlert.timestamp.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Timestamp', 'Source IP', 'Target IP', 'Alert Type', 'Severity'])
    
    for a in alerts:
        writer.writerow([a.id, a.timestamp.strftime('%Y-%m-%d %H:%M:%S'), a.src_ip, a.dst_ip, a.alert_type, a.severity])
        
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename=netguard_analytics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/api/analytics/reset', methods=['POST'])
@login_required
def reset_analytics():
    try:
        db.session.query(ThreatAlert).delete()
        db.session.commit()
        send_telegram_alert("⚠️ *NetGuard Alert*\nAll analytics data cleared.")
        return jsonify({'status': 'success', 'message': 'Data cleared successfully.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

# --- SECURE EXTERNAL THREAT TESTING ROUTE ---
@app.route('/api/test-threat', methods=['POST'])
def external_test_threat():
    data = request.get_json() or {}
    api_key = data.get('api_key') or request.headers.get('X-API-KEY')
    
    # Simple security key check so unauthorized web users cannot post fake alerts
    if api_key != "netguard-secret-123":
        return jsonify({'status': 'error', 'message': 'Unauthorized. Invalid API Key.'}), 401

    src_ip = data.get('src_ip', '172.20.10.1')       # Default to your Gateway
    dst_ip = data.get('dst_ip', '172.20.10.2')       # Default to your PC IP
    alert_type = data.get('alert_type', 'TCP SYN Port Scan')
    severity = data.get('severity', 'High')

    alert = ThreatAlert(
        src_ip=src_ip,
        dst_ip=dst_ip,
        alert_type=alert_type,
        severity=severity
    )
    db.session.add(alert)
    db.session.commit()

    if severity == "High":
        send_telegram_alert(
            f"🚨 *HIGH THREAT DETECTED*\n"
            f"Source IP: `{src_ip}`\n"
            f"Target IP: `{dst_ip}`\n"
            f"Type: `{alert_type}`"
        )

    return jsonify({
        'status': 'success',
        'message': f'Threat logged successfully for target {dst_ip}!'
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    sniffer_thread = threading.Thread(target=start_packet_sniffer, daemon=True)
    sniffer_thread.start()
    app.run(host='0.0.0.0', port=5000, debug=False)
