# language: Python, file: server.py, runtime: python 3.12, deps: flask (pip install flask)
# *watch for db.json growth - sessions list unbounded, prune to last 5000 in prod*
from flask import Flask, request, jsonify, render_template_string
import json, os, time, secrets
from datetime import datetime

app = Flask(__name__)
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "db.json")
SECRET = "CHANGE_THIS_TO_RANDOM_32_CHARS_1234"
VERSION = "1.0"
ADMINPASS = "admin123"
MAX_SESSION_HOURS = 2  # every login dies 2h after first bind, no exceptions

def load():
    if not os.path.exists(DB):
        return {"users": {}, "keys": {}, "sessions": []}
    with open(DB, "r") as f:
        d = json.load(f)
    if "sessions" not in d:
        d["sessions"] = []
    return d

def save(d):
    d["sessions"] = d.get("sessions", [])[-5000:]
    with open(DB, "w") as f:
        json.dump(d, f, indent=2)

def log_session(d, username, key, hwid, pc, ip, result):
    d.setdefault("sessions", []).append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ts": time.time(),
        "username": username,
        "key": key,
        "hwid": (hwid or "")[:32],
        "pc": pc or "-",
        "ip": ip,
        "result": result
    })

def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)

@app.route("/api/init", methods=["POST"])
def init():
    if request.form.get("secret") != SECRET:
        return jsonify(success=False, message="bad secret")
    if request.form.get("ver") != VERSION:
        return jsonify(success=False, message="update required")
    return jsonify(success=True, message="initialized")

@app.route("/api/license", methods=["POST"])
def license():
    d = load()
    if request.form.get("secret") != SECRET:
        return jsonify(success=False, message="bad secret")
    key = request.form.get("key", "").strip()
    hwid = request.form.get("hwid", "").strip()
    username = request.form.get("username", "user").strip() or "user"
    pc = request.form.get("pc", "-").strip() or "-"
    ip = client_ip()

    if key not in d["keys"]:
        log_session(d, username, key, hwid, pc, ip, "invalid key")
        save(d)
        return jsonify(success=False, message="invalid key")
    k = d["keys"][key]
    if k["status"] == "banned":
        log_session(d, username, key, hwid, pc, ip, "banned")
        save(d)
        return jsonify(success=False, message="key banned")
    if k["status"] == "used":
        u = d["users"].get(k["used_by"])
        if not u:
            log_session(d, username, key, hwid, pc, ip, "user missing")
            save(d)
            return jsonify(success=False, message="user missing")
        if u.get("hwid") != hwid:
            log_session(d, k["used_by"], key, hwid, pc, ip, "hwid mismatch")
            save(d)
            return jsonify(success=False, message="hwid mismatch")
        if u.get("subscription", 0) < time.time():
            log_session(d, k["used_by"], key, hwid, pc, ip, "expired")
            save(d)
            return jsonify(success=False, message="subscription expired")
        if u.get("hard_deadline", 0) and u["hard_deadline"] < time.time():
            log_session(d, k["used_by"], key, hwid, pc, ip, "2h session over")
            save(d)
            return jsonify(success=False, message="2 hour session ended")
        log_session(d, k["used_by"], key, hwid, pc, ip, "ok")
        u["last_ip"] = ip
        u["last_pc"] = pc
        u["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        save(d)
        return jsonify(success=True, message="authenticated", username=k["used_by"], expiry=u["subscription"])
    # first use - bind it (capped at MAX_SESSION_HOURS no matter the key length)
    days = k["duration_days"]
    expiry = time.time() + (days * 86400)
    hard_deadline = time.time() + (MAX_SESSION_HOURS * 3600)
    if expiry > hard_deadline:
        expiry = hard_deadline
    d["users"][username] = {"hwid": hwid, "subscription": expiry,
        "hard_deadline": hard_deadline,
        "pc": pc, "last_ip": ip, "last_pc": pc,
        "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    k["status"] = "used"
    k["used_by"] = username
    log_session(d, username, key, hwid, pc, ip, "first login (bound)")
    save(d)
    return jsonify(success=True, message="authenticated", username=username, expiry=expiry)

ADMIN_HTML = """
<!DOCTYPE html><html><head><title>KeyAuth Panel</title>
<style>
body{font-family:Arial;background:#0f0f1a;color:#fff;padding:30px}h1{color:#7c5cff}
.card{background:#1a1a2e;padding:20px;border-radius:10px;margin:15px 0}
input,select{padding:8px;margin:5px;border-radius:5px;border:none}
button{background:#7c5cff;color:#fff;padding:8px 16px;border:none;border-radius:5px;cursor:pointer}
button.red{background:#cc3355}button.green{background:#22aa66}
table{width:100%;border-collapse:collapse;margin-top:10px;font-size:13px}
td,th{padding:8px;border-bottom:1px solid #333;text-align:left}
.used{color:#ffaa00}.unused{color:#00ff88}.banned{color:#ff4444}
.ok{color:#00ff88}.fail{color:#ff5555}
.stats{display:flex;gap:15px}.stat{background:#1a1a2e;padding:15px 25px;border-radius:10px;text-align:center}
.stat b{font-size:24px;color:#7c5cff}
</style></head>
<body><h1>🔑 VARENT LOCK — Admin Panel</h1>
<div class="stats">
<div class="stat"><b>{{keys|length}}</b><br>Total Keys</div>
<div class="stat"><b>{{users|length}}</b><br>Active Users</div>
<div class="stat"><b>{{sessions|length}}</b><br>Total Logins</div>
</div>
<div class="card"><h3>Create Key</h3>
<form method="POST" action="/admin/create">
<input name="adminpass" type="password" placeholder="Admin password" required>
<select name="days"><option value="0.083">2 hours (trial)</option><option value="1">1 day</option><option value="7">7 days</option><option value="30">30 days</option><option value="365">1 year</option></select>
<input name="qty" type="number" value="1" min="1" max="1000" style="width:80px" title="How many keys">
<button>Create</button></form>
<form method="POST" action="/admin/export"><input name="adminpass" type="password" placeholder="Admin password" required>
<button>Export unused keys (.txt)</button></form></div>
<div class="card"><h3>Keys ({{keys|length}})</h3>
<table><tr><th>Key</th><th>Days</th><th>Status</th><th>User</th><th>HWID</th><th>PC</th><th>Last IP</th><th>Logins</th><th>Action</th></tr>
{% for k,v in keys.items() %}
<tr><td><code>{{k}}</code></td><td>{{v.duration_days}}</td>
<td class="{{v.status}}">{{v.status}}</td><td>{{v.used_by or '-'}}</td>
<td><code>{{users.get(v.used_by, {}).get('hwid','-')[:16]}}</code></td>
<td>{{users.get(v.used_by, {}).get('last_pc','-')}}</td>
<td>{{users.get(v.used_by, {}).get('last_ip','-')}}</td>
<td>{{counts.get(k,0)}}</td>
<td><a href="/admin/ban?key={{k}}&p={{adminpass}}"><button class="red">Ban</button></a>
<a href="/admin/reset?key={{k}}&p={{adminpass}}"><button class="green">Reset</button></a></td></tr>
{% endfor %}</table></div>
<div class="card"><h3>🖥️ Live Sessions — last {{sessions|length}} logins</h3>
<table><tr><th>Time</th><th>User</th><th>Key</th><th>PC Name</th><th>HWID</th><th>IP</th><th>Result</th></tr>
{% for s in sessions|reverse %}
<tr><td>{{s.time}}</td><td>{{s.username}}</td><td><code>{{s.key[:18]}}</code></td>
<td>{{s.pc}}</td><td><code>{{s.hwid[:16]}}</code></td><td>{{s.ip}}</td>
<td class="{{'ok' if s.result=='ok' or 'bound' in s.result else 'fail'}}">{{s.result}}</td></tr>
{% endfor %}</table></div></body></html>
"""

@app.route("/admin")
def admin():
    d = load()
    p = request.args.get("p", "")
    counts = {}
    for s in d.get("sessions", []):
        if s.get("result") == "ok" or "bound" in s.get("result", ""):
            counts[s["key"]] = counts.get(s["key"], 0) + 1
    sess = d.get("sessions", [])[-100:][::-1]
    # show newest first, cap 100
    return render_template_string(ADMIN_HTML, keys=d["keys"], users=d.get("users", {}),
        sessions=list(reversed(sess)), counts=counts, adminpass=p)

@app.route("/admin/create", methods=["POST"])
def admin_create():
    if request.form.get("adminpass") != ADMINPASS:
        return "wrong password", 403
    d = load()
    days = float(request.form.get("days", 30))
    try:
        qty = max(1, min(1000, int(request.form.get("qty", 1))))
    except Exception:
        qty = 1
    made = []
    for _ in range(qty):
        key = "KEY-" + secrets.token_hex(8).upper()
        d["keys"][key] = {"duration_days": days, "status": "unused", "used_by": None}
        made.append(key)
    save(d)
    rows = "<br>".join(f"<code>{k}</code>" for k in made)
    return f'Created {len(made)} key(s) ({days} days each):<br>{rows}<br><br><a href="/admin?p={ADMINPASS}">Back</a>'

@app.route("/admin/export", methods=["POST"])
def admin_export():
    from flask import Response
    if request.form.get("adminpass") != ADMINPASS:
        return "wrong password", 403
    d = load()
    lines = [k for k, v in d["keys"].items() if v["status"] == "unused"]
    txt = "\n".join(lines)
    return Response(txt, mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=unused_keys.txt"})

@app.route("/admin/ban")
def admin_ban():
    if request.args.get("p") != ADMINPASS:
        return "wrong password", 403
    d = load()
    k = request.args.get("key")
    if k in d["keys"]:
        d["keys"][k]["status"] = "banned"
        save(d)
    return f'Banned {k} <br><a href="/admin?p={ADMINPASS}">Back</a>'

@app.route("/admin/reset")
def admin_reset():
    if request.args.get("p") != ADMINPASS:
        return "wrong password", 403
    d = load()
    k = request.args.get("key")
    if k in d["keys"]:
        old = d["keys"][k].get("used_by")
        if old and old in d.get("users", {}):
            del d["users"][old]
        d["keys"][k]["status"] = "unused"
        d["keys"][k]["used_by"] = None
        save(d)
    return f'Reset {k} (HWID unbound, reusable) <br><a href="/admin?p={ADMINPASS}">Back</a>'

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("=" * 50)
    print("  KeyAuth Clone running!")
    print(f"  Admin: http://127.0.0.1:{port}/admin?p=admin123")
    print("=" * 50)
    app.run(host="0.0.0.0", port=port, threaded=True)
