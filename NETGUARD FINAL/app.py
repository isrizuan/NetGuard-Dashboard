import os
import threading
import requests
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from scapy.all import sniff, IP, TCP, UDP, ICMP

app = Flask(__name__)
app.config['SECRET_KEY'] = 'netguard-standalone-2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///netguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Telegram Alert Setup ---
TELEGRAM_BOT_TOKEN = "8396604449:AAHFWdCXrcPAD7qfSYbmyT6LfpqniEF3ZhE"
TELEGRAM_CHAT_ID = "943418259"

def send_telegram_alert(message):
    if TELEGRAM_BOT_TOKEN != "YOUR_TELEGRAM_BOT_TOKEN":
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }
        try:
            response = requests.post(url, json=payload, timeout=5)
            res_data = response.json()
            if not res_data.get("ok"):
                print(f"❌ Telegram API Error: {res_data.get('description')}")
            else:
                print("✅ Telegram message sent successfully!")
        except Exception as e:
            print(f"❌ Network/Request Error: {e}")

# --- Authentication & Models ---
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

# --- Python Live Packet Monitor Thread ---
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        with app.app_context():
            # Check if either src or dst matches an IP set to 'is_monitoring=True'
            monitored_targets = [t.ip_address for t in TargetIP.query.filter_by(is_monitoring=True).all()]

            if src_ip in monitored_targets or dst_ip in monitored_targets:
                alert_type = None
                severity = "Low"

                # Detect TCP SYN Port Scan / Connection attempts
                if TCP in packet and packet[TCP].flags == 'S':
                    alert_type = "TCP Port Scan / Connection Init"
                    severity = "High"
                # Detect ICMP Ping Probing
                elif ICMP in packet:
                    alert_type = "ICMP Ping Sweep Detected"
                    severity = "Medium"
                # Detect Suspicious UDP Traffic
                elif UDP in packet:
                    alert_type = "UDP Traffic Probe"
                    severity = "Low"

                if alert_type:
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
                            f"⚠️ *HIGH THREAT DETECTED*\n"
                            f"Source IP: `{src_ip}`\n"
                            f"Target IP: `{dst_ip}`\n"
                            f"Type: `{alert_type}`"
                        )

def start_packet_sniffer():
    # Continuously captures live packets on active network interfaces
    sniff(prn=packet_callback, store=0)

# --- Web Application Routes ---
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

# --- Web APIs ---
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
        send_telegram_alert(f"🚨 *NetGuard System Alert*\nMonitoring *{status}* for Target IP: `{ip}`")
        return jsonify({'status': 'success', 'is_monitoring': target.is_monitoring})
    return jsonify({'status': 'error', 'message': 'IP not found'}), 404

@app.route('/api/alerts/realtime', methods=['GET'])
@login_required
def get_realtime_alerts():
    alerts = ThreatAlert.query.order_by(ThreatAlert.timestamp.desc()).limit(10).all()
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
    alerts = ThreatAlert.query.order_by(ThreatAlert.timestamp.asc()).all()
    severity_counts = {'High': 0, 'Medium': 0, 'Low': 0}
    for a in alerts:
        if a.severity in severity_counts:
            severity_counts[a.severity] += 1
            
    return jsonify({
        'total_alerts': len(alerts),
        'severity_distribution': severity_counts,
        'alerts': [{
            'id': a.id,
            'src_ip': a.src_ip,
            'dst_ip': a.dst_ip,
            'alert_type': a.alert_type,
            'severity': a.severity,
            'timestamp': a.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        } for a in alerts]
    })

@app.route('/api/analytics/reset', methods=['POST'])
@login_required
def reset_analytics():
    try:
        db.session.query(ThreatAlert).delete()
        db.session.commit()
        send_telegram_alert("⚠️ *NetGuard System Alert*\nAll monitored threat analytics data has been reset.")
        return jsonify({'status': 'success', 'message': 'All captured data cleared successfully.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    # Launch network packet monitor on a background thread
    sniffer_thread = threading.Thread(target=start_packet_sniffer, daemon=True)
    sniffer_thread.start()

    app.run(host='0.0.0.0', port=5000, debug=False)