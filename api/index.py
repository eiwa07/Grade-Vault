"""
GradeVault — Vercel Serverless API (Production-optimised)
"""

import os
import json
import random
import secrets
import hashlib
import time
from datetime import datetime, timedelta, timezone
from collections import defaultdict

import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify, abort
from flask_cors import CORS

# ── App ───────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, supports_credentials=True,
     origins=os.environ.get("ALLOWED_ORIGIN", "*"))

DATABASE_URL   = os.environ.get("DATABASE_URL", "")
SESSION_SECRET = os.environ.get("SESSION_SECRET", secrets.token_hex(16))
TOKEN_EXPIRY_HOURS = 72

SEMS = ["y1s1","y1s2","y2s1","y2s2","y3s1","y3s2","y4s1","y4s2","y5s1","y5s2"]

# ── Module-level connection ─────────────────────────────────
_conn     = None
_migrated = False

def get_conn():
    global _conn
    if not DATABASE_URL:
        raise Exception("DATABASE_URL not set")
    try:
        if _conn is None or _conn.closed:
            raise Exception("reconnect")
        _conn.isolation_level
    except Exception:
        _conn = psycopg2.connect(
            DATABASE_URL,
            cursor_factory=psycopg2.extras.RealDictCursor,
            connect_timeout=10,
        )
        _conn.autocommit = False
    return _conn

def run_migrations_once():
    global _migrated
    if _migrated:
        return
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id            SERIAL PRIMARY KEY,
                    username      TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at    TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token      TEXT PRIMARY KEY,
                    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    expires_at TIMESTAMPTZ NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS gpa_data (
                    user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    semesters  JSONB NOT NULL DEFAULT '{}',
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
        conn.commit()
        _migrated = True
    except Exception as e:
        try:
            conn.rollback()
        except:
            pass
        print(f"[WARN] Migration: {e}")

# ── Rate limiter ────────────────────────────────────────────
_fails = defaultdict(lambda: {"n": 0, "until": 0})

def check_rate(ip):
    e = _fails[ip]
    if e["until"] > time.time():
        abort(429, description="Too many attempts. Try again in 5 minutes.")

def fail(ip):
    e = _fails[ip]
    e["n"] += 1
    if e["n"] >= 10:
        e["until"] = time.time() + 300
        e["n"] = 0

def clear_fail(ip):
    _fails.pop(ip, None)

def record_fail(ip):
    fail(ip)

# ── Auth helpers ────────────────────────────────────────────
def hash_pw(password):
    return hashlib.sha256((SESSION_SECRET + password).encode()).hexdigest()

def make_token():
    return secrets.token_urlsafe(40)

def get_user_from_token(token):
    if not token:
        return None
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u.id, u.username
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.token = %s AND s.expires_at > NOW()
            """, (token,))
            row = cur.fetchone()
        return dict(row) if row else None
    except Exception:
        try:
            _conn.rollback()
        except:
            pass
        return None

def require_auth():
    token = request.headers.get("X-Auth-Token") or ""
    user = get_user_from_token(token)
    if not user:
        abort(401, description="Unauthorized")
    return user

def create_session(user_id):
    token = make_token()
    expires = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_HOURS)
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES (%s, %s, %s)",
            (token, user_id, expires)
        )
    conn.commit()
    return token

def load_semesters(user_id):
    base = {s: [] for s in SEMS}
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT semesters FROM gpa_data WHERE user_id = %s", (user_id,))
            row = cur.fetchone()
        if row:
            stored = row["semesters"]
            if isinstance(stored, str):
                stored = json.loads(stored)
            for s in SEMS:
                if s in stored and isinstance(stored[s], list):
                    base[s] = stored[s]
    except Exception:
        try:
            _conn.rollback()
        except:
            pass
    return base

def maybe_cleanup_sessions():
    if random.random() > 0.10:
        return
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM sessions WHERE expires_at < NOW()")
        conn.commit()
    except Exception:
        try:
            _conn.rollback()
        except:
            pass

# ── Routes ───────────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")

    check_rate(ip)

    if not username or len(username) < 2:
        return jsonify(error="Username must be at least 2 characters"), 400
    if len(username) > 32:
        return jsonify(error="Username too long (max 32 chars)"), 400
    if not password or len(password) < 4:
        return jsonify(error="Password must be at least 4 characters"), 400

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id",
                (username, hash_pw(password)),
            )
            user_id = cur.fetchone()["id"]
            empty = {s: [] for s in SEMS}
            cur.execute(
                "INSERT INTO gpa_data (user_id, semesters) VALUES (%s, %s)",
                (user_id, json.dumps(empty)),
            )
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        record_fail(ip)
        return jsonify(error="Username already taken"), 409
    except Exception as e:
        conn.rollback()
        return jsonify(error="Database error"), 500

    clear_fail(ip)
    token = create_session(user_id)
    semesters = {s: [] for s in SEMS}
    return jsonify(token=token, username=username, semesters=semesters), 201

@app.route("/api/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")

    check_rate(ip)

    if not username or not password:
        return jsonify(error="Username and password required"), 400

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, username FROM users WHERE username = %s AND password_hash = %s",
                (username, hash_pw(password)),
            )
            row = cur.fetchone()
    except Exception:
        conn.rollback()
        return jsonify(error="Database error"), 500

    if not row:
        fail(ip)
        return jsonify(error="Invalid username or password"), 401

    clear_fail(ip)
    maybe_cleanup_sessions()

    user_id = row["id"]
    token = create_session(user_id)
    semesters = load_semesters(user_id)
    return jsonify(token=token, username=row["username"], semesters=semesters), 200

@app.route("/api/logout", methods=["POST"])
def logout():
    token = request.headers.get("X-Auth-Token") or ""
    if token:
        try:
            conn = get_conn()
            with conn.cursor() as cur:
                cur.execute("DELETE FROM sessions WHERE token = %s", (token,))
            conn.commit()
        except Exception:
            try:
                _conn.rollback()
            except:
                pass
    return jsonify(ok=True)

@app.route("/api/data", methods=["GET"])
def get_data():
    user = require_auth()
    return jsonify(username=user["username"], semesters=load_semesters(user["id"]))

@app.route("/api/data", methods=["PUT"])
def save_data():
    user = require_auth()
    body = request.get_json(silent=True) or {}
    semesters = body.get("semesters")

    if not isinstance(semesters, dict):
        return jsonify(error="Invalid payload"), 400

    clean = {s: (semesters[s] if isinstance(semesters.get(s), list) else []) for s in SEMS}

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO gpa_data (user_id, semesters, updated_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (user_id) DO UPDATE
                    SET semesters = EXCLUDED.semesters,
                        updated_at = EXCLUDED.updated_at
            """, (user["id"], json.dumps(clean)))
        conn.commit()
    except Exception:
        conn.rollback()
        return jsonify(error="Database error"), 500

    return jsonify(ok=True)

@app.route("/api/health")
def health():
    return jsonify(status="ok", ts=datetime.now(timezone.utc).isoformat())

if __name__ == "__main__":
    app.run(debug=True, port=5000)
