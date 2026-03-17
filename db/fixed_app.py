"""
app_fixed.py — FIXED Flask application
Finding : FIND-0042
Endpoint: POST /api/v1/login
Parameter: username
Fix     : Parameterized queries via sqlite3 placeholder binding
DB Engine: SQLite (mirrors MySQL 8.0 behavior for this demo)

Fix applied at line 40 — compare directly with app.py line 40
"""

from flask import Flask, request, jsonify
import sqlite3
import hashlib
import os

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout =5)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# ------------------------------------------------------------------
# FIXED ENDPOINT
# ------------------------------------------------------------------
@app.route("/api/v1/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn   = get_db()
    cursor = conn.cursor()

    # FIX: parameterized query — username is bound as a value, never interpolated
    # The DB engine receives query structure and data separately
    # No matter what username contains, it cannot modify the query syntax
    query = "SELECT id, username, role, email FROM users WHERE username = ? AND password = ?"

    try:
        cursor.execute(query, (username, hash_password(password)))
        rows = cursor.fetchall()
    except Exception as e:
        # Generic error — no detail leaked to client
        return jsonify({
            "status" : "error",
            "message": "An internal error occurred"
        }), 500
    finally:
        conn.close()

    if rows:
        user = dict(rows[0])
        return jsonify({
            "status" : "success",
            "message": f"Welcome, {user['username']}",
        }), 200
    else:
        return jsonify({
            "status" : "fail",
            "message": "Invalid credentials"
        }), 401


# ------------------------------------------------------------------
# HEALTH CHECK
# ------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "running", "app": "fixed"}), 200


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print("[!] Database not found. Run: python db/seed.py")
        exit(1)
    print("[+] Running FIXED app on port 5001")
    app.run(debug=False, port=5001)