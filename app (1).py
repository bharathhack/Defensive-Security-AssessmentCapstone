"""Fictional student portal, v2 (AFTER fixes).

Lab use only: binds to 127.0.0.1. All users and passwords are synthetic.
"""
import logging
import os
import secrets
import sqlite3
import time
from collections import defaultdict, deque

from flask import Flask, abort, jsonify, request, session
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

LOG_PATH = os.environ.get("AUTH_LOG", os.path.join(os.path.dirname(__file__), "auth.log"))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(DEBUG=False, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=False)  # Secure=True behind HTTPS

logging.basicConfig(filename=LOG_PATH, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("portal.auth")

db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, pw_hash TEXT)")
db.execute("CREATE TABLE students (id INTEGER PRIMARY KEY, name TEXT, grade TEXT)")
db.executemany("INSERT INTO users (username, pw_hash) VALUES (?, ?)",
               [("student1", generate_password_hash("Lab-Only-Str0ng-Pass!")),
                ("admin", generate_password_hash("Lab-Only-Adm1n-Pass!"))])
db.executemany("INSERT INTO students (name, grade) VALUES (?, ?)",
               [("Alice Example", "A"), ("Bob Example", "B"), ("Chandra Example", "C")])
db.commit()

MAX_FAILS, WINDOW = 5, 60
fails = defaultdict(deque)


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/")
def index():
    return "Student Portal (lab v2)"


@app.post("/login")
def login():
    ip = request.remote_addr or "?"
    now = time.time()
    q = fails[ip]
    while q and now - q[0] > WINDOW:
        q.popleft()
    if len(q) >= MAX_FAILS:
        log.warning("auth_locked ip=%s", ip)
        return "too many attempts", 429

    u = request.form.get("username", "")[:64]
    p = request.form.get("password", "")[:128]
    row = db.execute("SELECT id, pw_hash FROM users WHERE username=?", (u,)).fetchone()
    if row and check_password_hash(row[1], p):
        session["uid"] = row[0]
        log.info("auth_success user=%s ip=%s", u, ip)
        return "ok"
    q.append(now)
    log.warning("auth_failure user=%s ip=%s", u, ip)
    return "invalid credentials", 401


@app.get("/search")
def search():
    return f"<h1>Results for {escape(request.args.get('q', ''))}</h1>"


@app.get("/student")
def student():
    sid = request.args.get("id", "1")
    if not sid.isdigit():
        abort(400)
    rows = db.execute("SELECT name, grade FROM students WHERE id = ?", (int(sid),)).fetchall()
    return jsonify(rows)


@app.errorhandler(Exception)
def generic_error(_e):
    code = getattr(_e, "code", 500)
    return jsonify(error="request failed"), code


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002)
