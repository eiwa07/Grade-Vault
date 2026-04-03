"""
GradeVault — Optimised Vercel Serverless API
─────────────────────────────────────────────
Auth:     Stateless JWT (HMAC-SHA256) — zero DB queries per request
Database: Neon PostgreSQL via pooled connection (no TCP overhead)
Storage:  ~2 KB per user (JSONB) — 0.5 GB free tier holds ~250,000 users

Env vars (set in Vercel dashboard):
  DATABASE_URL   — Neon **pooled** connection string  (use the -pooler URL)
  SESSION_SECRET — any random 32+ character string
"""

import os, json, hmac, hashlib, base64, time
from datetime import datetime, timezone

import psycopg2, psycopg2.extras
from flask import Flask, request, jsonify, abort
from flask_cors import CORS

app = Flask(__name__)
CORS(app, supports_credentials=True,
     origins=os.environ.get("ALLOWED_ORIGIN", "*"))

DATABASE_URL   = os.environ["DATABASE_URL"]
SESSION_SECRET = os.environ.get("SESSION_SECRET", "change-me-in-production")
TOKEN_TTL_SEC  = 72 * 3600

SEMS = ["y1s1","y1s2","y2s1","y2s2","y3s1","y3s2","y4s1","y4s2","y5s1","y5s2"]


# ── Database — reuse connection across warm invocations ───────
_conn = None

def get_conn():
    global _conn
    try:
        if _conn and not _conn.closed:
            _conn.cursor().execute("SELECT 1")
            return _conn
    except Exception:
        pass
    _conn = psycopg2.connect(
        DATABASE_URL,
        cursor_factory=psycopg2.extras.RealDictCursor,
        connect_timeout=8,
        keepalives=1,
        keepalives_idle=30,
        options="-c statement_timeout=8000",
    )
    _conn.autocommit = False
    return _conn


_migrated = False

def ensure_migrated():
    global _migrated
    if _migrated:
        return
    conn = get_conn()
    with conn.cursor() as cur:
        # No sessions table — JWT is stateless
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            SERIAL PRIMARY KEY,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at    TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_username_lower
            ON users (LOWER(username))
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS gpa_data (
                user_id    INTEGER PRIMARY KEY
                           REFERENCES users(id) ON DELETE CASCADE,
                semesters  JSONB    NOT NULL DEFAULT '{}',
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
    conn.commit()
    _migrated = True


# ── JWT — stateless auth, 0 DB queries per request ───────────
def _b64(b):    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def _unb64(s):
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (pad % 4))
def _sign(p64): return _b64(hmac.new(SESSION_SECRET.encode(), p64.encode(), hashlib.sha256).digest())

def make_token(uid, username):
    p64 = _b64(json.dumps({"u":uid,"n":username,"e":int(time.time())+TOKEN_TTL_SEC}, separators=(",",":")).encode())
    return f"{p64}.{_sign(p64)}"

def verify_token(tok):
    if not tok or tok.count(".") != 1:
        return None
    p64, sig = tok.rsplit(".", 1)
    if not hmac.compare_digest(_sign(p64), sig):
        return None
    try:
        payload = json.loads(_unb64(p64))
        return payload if payload.get("e",0) >= time.time() else None
    except Exception:
        return None

def require_auth():
    p = verify_token(request.headers.get("X-Auth-Token",""))
    if not p: abort(401, "Unauthorized")
    return {"id": p["u"], "username": p["n"]}

def hash_pw(pw): return hmac.new(SESSION_SECRET.encode(), pw.encode(), hashlib.sha256).hexdigest()
def empty_sems(): return {s: [] for s in SEMS}


# ── Error handlers ────────────────────────────────────────────
@app.errorhandler(400)
def bad_request(e): return jsonify(error=str(e.description)), 400
@app.errorhandler(401)
def unauthorized(e): return jsonify(error=str(e.description)), 401
@app.errorhandler(409)
def conflict(e): return jsonify(error=str(e.description)), 409
@app.errorhandler(500)
def server_error(e): return jsonify(error="Internal server error"), 500


# ── Register ──────────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    ensure_migrated()
    b = request.get_json(silent=True) or {}
    username = (b.get("username") or "").strip()
    password =  b.get("password") or ""

    if not username or len(username) < 2:
        return jsonify(error="Username must be at least 2 characters"), 400
    if len(username) > 32:
        return jsonify(error="Username too long (max 32)"), 400
    if not password or len(password) < 4:
        return jsonify(error="Password must be at least 4 characters"), 400

    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("INSERT INTO users (username,password_hash) VALUES (%s,%s) RETURNING id",
                        (username, hash_pw(password)))
            uid = cur.fetchone()["id"]
            cur.execute("INSERT INTO gpa_data (user_id,semesters) VALUES (%s,%s)",
                        (uid, json.dumps(empty_sems())))
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        get_conn().rollback()
        return jsonify(error="Username already taken"), 409
    except Exception:
        try: get_conn().rollback()
        except: pass
        return jsonify(error="Database error"), 500

    return jsonify(token=make_token(uid, username), username=username), 201


# ── Login ─────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    ensure_migrated()
    b = request.get_json(silent=True) or {}
    username = (b.get("username") or "").strip()
    password =  b.get("password") or ""

    if not username or not password:
        return jsonify(error="Username and password required"), 400

    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT id, username FROM users WHERE LOWER(username)=LOWER(%s) AND password_hash=%s",
                        (username, hash_pw(password)))
            row = cur.fetchone()
    except Exception:
        return jsonify(error="Database error"), 500

    if not row:
        return jsonify(error="Invalid username or password"), 401

    return jsonify(token=make_token(row["id"], row["username"]), username=row["username"]), 200


# ── Logout (stateless — client drops token) ───────────────────
@app.route("/api/logout", methods=["POST"])
def logout():
    return jsonify(ok=True)


# ── GET data ──────────────────────────────────────────────────
@app.route("/api/data", methods=["GET"])
def get_data():
    ensure_migrated()
    user = require_auth()
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT semesters FROM gpa_data WHERE user_id=%s", (user["id"],))
            row = cur.fetchone()
    except Exception:
        return jsonify(error="Database error"), 500

    sems = empty_sems()
    if row:
        stored = row["semesters"]
        if isinstance(stored, str): stored = json.loads(stored)
        for s in SEMS:
            if s in stored and isinstance(stored[s], list):
                sems[s] = stored[s]

    return jsonify(username=user["username"], semesters=sems)


# ── PUT data ──────────────────────────────────────────────────
@app.route("/api/data", methods=["PUT"])
def save_data():
    ensure_migrated()
    user = require_auth()
    b = request.get_json(silent=True) or {}
    sems = b.get("semesters")
    if not isinstance(sems, dict):
        return jsonify(error="Invalid payload"), 400

    clean = {s: (sems.get(s) if isinstance(sems.get(s), list) else []) for s in SEMS}

    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO gpa_data (user_id, semesters, updated_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (user_id) DO UPDATE
                  SET semesters=EXCLUDED.semesters, updated_at=EXCLUDED.updated_at
            """, (user["id"], json.dumps(clean)))
        conn.commit()
    except Exception:
        try: get_conn().rollback()
        except: pass
        return jsonify(error="Database error"), 500

    return jsonify(ok=True)


# ── Health ────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    return jsonify(status="ok", ts=datetime.now(timezone.utc).isoformat())


if __name__ == "__main__":
    app.run(debug=True, port=5000)
