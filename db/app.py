"""
app.py — VULNERABLE Flask application
Finding : FIND-0042
Endpoint: POST /api/v1/login
Parameter: username
Vulnerability: SQL Injection via raw string interpolation
DB Engine: SQLite (mirrors MySQL 8.0 behavior for this demo)
!! THIS APP IS INTENTIONALLY VULNERABLE — DO NOT DEPLOY !!
"""
from flask import Flask, request, jsonify
import sqlite3
import hashlib
import os

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# ------------------------------------------------------------------
# VULNERABLE ENDPOINT
# ------------------------------------------------------------------
@app.route("/api/v1/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn   = get_db()
    cursor = conn.cursor()

    query = f"SELECT id, username, role, email FROM users WHERE username = '{username}' AND password = '{hash_password(password)}'"

    # DEBUG — shows raw query in Flask terminal
   # print(f"[DEBUG] Query: {query}")

    try:
        cursor.execute(query)
        rows = cursor.fetchall()
    except Exception as e:
        return jsonify({
            "status"  : "error",
            "message" : str(e),
            "query"   : query
        }), 500
    finally:
        conn.close()

    if rows:
        users = [dict(row) for row in rows]
        return jsonify({
            "status"      : "success",
            "message"     : f"Welcome, {users[0]['username']}",
            "user_count"  : len(users),
            "users"       : users
        }), 200
    else:
        return jsonify({
            "status"  : "fail",
            "message" : "Invalid credentials"
        }), 401

# ------------------------------------------------------------------
# HEALTH CHECK
# ------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "running", "app": "vulnerable"}), 200

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print("[!] Database not found. Run: python db/seed.py")
        exit(1)
    print("[!] WARNING: Running VULNERABLE app on port 5000")
    app.run(debug=True, port=5000)