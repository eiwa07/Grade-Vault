import os, json, hmac, hashlib, secrets, time
from datetime import datetime, timezone
from collections import defaultdict

import psycopg2, psycopg2.extras
import jwt
from flask import Flask, request, jsonify, abort
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=os.environ.get("ALLOWED_ORIGIN", "*"))

SECRET  = os.environ.get("SESSION_SECRET", secrets.token_hex(16))
DB_URL  = os.environ.get("DATABASE_URL", "")
TTL     = 72 * 3600
ALG     = "HS256"
SEMS    = ["y1s1","y1s2","y2s1","y2s2","y3s1","y3s2","y4s1","y4s2","y5s1","y5s2"]

# ── Rate limiter ──────────────────────────────────────────────
_rl: dict = defaultdict(list)
def allow(key, limit, window=60):
    now = time.monotonic()
    _rl[key] = [t for t in _rl[key] if now - t < window]
    if len(_rl[key]) >= limit: return False
    _rl[key].append(now); return True

def get_ip():
    return (request.headers.get("X-Forwarded-For","").split(",")[0].strip()
            or request.remote_addr or "?")

# ── DB ────────────────────────────────────────────────────────
def db():
    return psycopg2.connect(DB_URL,
        cursor_factory=psycopg2.extras.RealDictCursor,
        connect_timeout=8)

_migrated = False
def ensure_schema():
    global _migrated
    if _migrated: return
    with db() as c:
        with c.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )""")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS gpa_data (
                    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    semesters JSONB NOT NULL DEFAULT '{}',
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                )""")
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_lower
                ON users(LOWER(username))""")
        c.commit()
    _migrated = True

try: ensure_schema()
except Exception as e: print(f"[schema] {e}")

# ── Auth ──────────────────────────────────────────────────────
def pw(password): return hmac.new(SECRET.encode(), password.encode(), hashlib.sha256).hexdigest()
def mint(uid, username): return jwt.encode({"sub":uid,"usr":username,"exp":int(time.time())+TTL}, SECRET, ALG)
def decode(token):
    try:
        p = jwt.decode(token, SECRET, algorithms=[ALG], options={"require":["sub","usr","exp"]})
        return {"id": p["sub"], "username": p["usr"]}
    except: return None

def auth():
    u = decode(request.headers.get("X-Auth-Token",""))
    if not u: abort(401, "Session expired")
    return u

def empty(): return {s: [] for s in SEMS}
def clean(raw): return {s: (raw[s] if isinstance(raw.get(s), list) else []) for s in SEMS}

# ── Error handlers ────────────────────────────────────────────
@app.errorhandler(400) 
def e400(e): return jsonify(error=str(e.description)), 400
@app.errorhandler(401)
def e401(e): return jsonify(error=str(e.description)), 401
@app.errorhandler(409)
def e409(e): return jsonify(error=str(e.description)), 409
@app.errorhandler(429)
def e429(e): return jsonify(error="Too many requests"), 429

# ── Register ──────────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    if not allow(f"auth:{get_ip()}", 10): abort(429)
    b = request.get_json(silent=True) or {}
    u = (b.get("username") or "").strip()
    p = b.get("password") or ""
    if len(u) < 2:  return jsonify(error="Username too short"), 400
    if len(u) > 32: return jsonify(error="Username too long"), 400
    if len(p) < 4:  return jsonify(error="Password too short (min 4)"), 400
    try:
        with db() as c:
            with c.cursor() as cur:
                cur.execute("INSERT INTO users(username,password_hash) VALUES(%s,%s) RETURNING id", (u, pw(p)))
                uid = cur.fetchone()["id"]
                cur.execute("INSERT INTO gpa_data(user_id,semesters) VALUES(%s,%s)", (uid, json.dumps(empty())))
            c.commit()
    except psycopg2.errors.UniqueViolation: return jsonify(error="Username taken"), 409
    except Exception as e: return jsonify(error=f"DB error: {e}"), 500
    return jsonify(token=mint(uid, u), username=u), 201

# ── Login ─────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    if not allow(f"auth:{get_ip()}", 10): abort(429)
    b = request.get_json(silent=True) or {}
    u = (b.get("username") or "").strip()
    p = b.get("password") or ""
    if not u or not p: return jsonify(error="Username and password required"), 400
    try:
        with db() as c:
            with c.cursor() as cur:
                cur.execute("SELECT id,username FROM users WHERE LOWER(username)=LOWER(%s) AND password_hash=%s", (u, pw(p)))
                row = cur.fetchone()
    except Exception as e: return jsonify(error=f"DB error: {e}"), 500
    if not row: return jsonify(error="Invalid username or password"), 401
    return jsonify(token=mint(row["id"], row["username"]), username=row["username"]), 200

# ── Logout ────────────────────────────────────────────────────
@app.route("/api/logout", methods=["POST"])
def logout():
    return jsonify(ok=True)  # JWT — client drops the token

# ── GET data ──────────────────────────────────────────────────
@app.route("/api/data", methods=["GET"])
def get_data():
    user = auth()
    try:
        with db() as c:
            with c.cursor() as cur:
                cur.execute("SELECT semesters, updated_at FROM gpa_data WHERE user_id=%s", (user["id"],))
                row = cur.fetchone()
    except Exception as e: return jsonify(error=f"DB error: {e}"), 500
    sems = empty(); ts = None
    if row:
        raw = row["semesters"]
        if isinstance(raw, str): raw = json.loads(raw)
        sems = clean(raw)
        ts   = row["updated_at"].isoformat() if row["updated_at"] else None
    return jsonify(username=user["username"], semesters=sems, updated_at=ts)

# ── PUT data ──────────────────────────────────────────────────
@app.route("/api/data", methods=["PUT"])
def save_data():
    user = auth()
    b = request.get_json(silent=True) or {}
    sems = b.get("semesters")
    if not isinstance(sems, dict): return jsonify(error="Bad payload"), 400
    c_data = json.dumps(clean(sems), separators=(",",":"), sort_keys=True)
    h      = hashlib.sha256(c_data.encode()).hexdigest()[:16]
    if b.get("hash") == h: return jsonify(ok=True, skipped=True, hash=h)
    try:
        with db() as c:
            with c.cursor() as cur:
                cur.execute("""
                    INSERT INTO gpa_data(user_id,semesters,updated_at) VALUES(%s,%s,NOW())
                    ON CONFLICT(user_id) DO UPDATE
                        SET semesters=EXCLUDED.semesters, updated_at=EXCLUDED.updated_at
                    RETURNING updated_at""", (user["id"], c_data))
                ts = cur.fetchone()["updated_at"].isoformat()
            c.commit()
    except Exception as e: return jsonify(error=f"DB error: {e}"), 500
    return jsonify(ok=True, hash=h, updated_at=ts)

# ── Health ────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    return jsonify(status="ok", ts=datetime.now(timezone.utc).isoformat())
