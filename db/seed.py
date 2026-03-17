import sqlite3
import hashlib
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

USERS = [
    ("admin",       "superSecret123"),
    ("alice.jones", "Passw0rd!"),
    ("bob.smith",   "qwerty2024"),
    ("carol.white", "C@rolSecure99"),
    ("dave.brown",  "letmein!1"),
    ("eve.davis",   "3v3Secure!"),
    ("frank.miller","Fr@nk2024!"),
    ("grace.lee",   "Gr@ce#9988"),
    ("henry.wilson","H3nryPass!"),
    ("ivy.moore",   "1vyM00re@"),
]

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def seed():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("""
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'user',
            email    TEXT NOT NULL
        )
    """)

    for i, (username, password) in enumerate(USERS):
        role  = "admin" if username == "admin" else "user"
        email = f"{username.replace('.', '_')}@corp.internal"
        cursor.execute(
            "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), role, email)
        )

    conn.commit()
    conn.close()
    print(f"[+] Database seeded at {DB_PATH}")
    print(f"[+] {len(USERS)} users created")
    print("\nUsers:")
    for username, password in USERS:
        print(f"  {username:<20} password: {password}")

if __name__ == "__main__":
    seed()