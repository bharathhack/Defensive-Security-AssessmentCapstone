"""Fictional student portal, v1 (BEFORE fixes).

Lab use only: binds to 127.0.0.1. All users and passwords are synthetic.
This version contains deliberate weaknesses so they can be assessed and fixed.
"""
import sqlite3

from flask import Flask, jsonify, request, session

app = Flask(__name__)
app.secret_key = "dev"          # weak, hard-coded secret
app.config["DEBUG"] = True

db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
db.execute("CREATE TABLE students (id INTEGER PRIMARY KEY, name TEXT, grade TEXT)")
db.executemany("INSERT INTO users (username, password) VALUES (?, ?)",
               [("student1", "password123"), ("admin", "admin")])  # synthetic, plaintext
db.executemany("INSERT INTO students (name, grade) VALUES (?, ?)",
               [("Alice Example", "A"), ("Bob Example", "B"), ("Chandra Example", "C")])
db.commit()


@app.get("/")
def index():
    return "Student Portal (lab v1)"


@app.get("/debug-info")
def debug_info():
    # Misconfiguration: leaks internals
    return jsonify(debug=app.config["DEBUG"], secret_key=app.secret_key,
                   routes=[str(r) for r in app.url_map.iter_rules()])


@app.post("/login")
def login():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    row = db.execute("SELECT id FROM users WHERE username=? AND password=?", (u, p)).fetchone()
    if row:
        session["uid"] = row[0]
        return "ok"
    return "invalid credentials", 401      # no rate limit, no logging


@app.get("/search")
def search():
    q = request.args.get("q", "")
    return f"<h1>Results for {q}</h1>"     # reflected, unescaped


@app.get("/student")
def student():
    sid = request.args.get("id", "1")
    sql = "SELECT name, grade FROM students WHERE id = " + sid   # string concatenation
    rows = db.execute(sql).fetchall()                            # errors bubble up
    return jsonify(rows)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)
