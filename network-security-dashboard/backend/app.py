from flask import Flask, jsonify
from flask_cors import CORS
import sqlite3
import json
import os

app = Flask(__name__)
CORS(app)

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'security.db')
LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'logs', 'network_logs.json')


def get_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


@app.route("/")
def home():
    return jsonify({"status": "running", "message": "Network Security Dashboard API"})


@app.route("/alerts")
def alerts():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()
    result = [{"id": r["id"], "ip": r["ip"], "alert": r["alert"]} for r in rows]
    return jsonify(result)


@app.route("/logs")
def logs():
    entries = []
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    return jsonify(entries[-50:])


@app.route("/statistics")
def statistics():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as total FROM alerts")
    total_alerts = cursor.fetchone()["total"]
    cursor.execute("SELECT ip, COUNT(*) as count FROM alerts GROUP BY ip ORDER BY count DESC LIMIT 5")
    top_ips = [{"ip": r["ip"], "count": r["count"]} for r in cursor.fetchall()]
    conn.close()

    total_packets = 0
    protocol_counts = {}
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        total_packets += 1
                        proto = entry.get("protocol", "unknown")
                        proto_name = "TCP" if proto == 6 else "UDP" if proto == 17 else "Other"
                        protocol_counts[proto_name] = protocol_counts.get(proto_name, 0) + 1
                    except json.JSONDecodeError:
                        continue

    return jsonify({
        "total_packets": total_packets,
        "total_alerts": total_alerts,
        "top_suspicious_ips": top_ips,
        "protocol_distribution": protocol_counts
    })


if __name__ == "__main__":
    app.run(debug=True)