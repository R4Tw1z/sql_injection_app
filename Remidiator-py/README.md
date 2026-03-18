# Remediator-py — SQL Injection Remediation Verification Tool

A generic, pipeline-ready tool that verifies whether SQL injection vulnerabilities have been properly remediated. Pass any target URL and payload list. the tool handles the rest.

---

## How It Works

On each run the tool performs three phases. First, a **reachability check** confirms the target is live. Second, a **dynamic baseline** is established by sending two clean requests and computing the SHA-256 hash of the response no manual hash configuration needed. Third, each payload is fired and the response is compared against the baseline across three anomaly vectors: response hash deviation, HTTP status code change, and response time exceeding the 4-second threshold.

---

## Requirements

```bash
pip install requests
python --version  # Python 3.10+
```

---

## Usage

```bash
# Against any target — just change the URL
python verify.py config.json --target http://localhost:5000/api/v1/login

# Against fixed app — same command, different port
python verify.py config.json --target http://localhost:5001/api/v1/login

# Against any public endpoint
python verify.py config.json --target https://staging.target.com/api/login
```

No editing `config.json` to switch targets. Baseline is recomputed fresh every run.

---

## Config Format

`config.json` contains three fields - finding type, parameter name, and payload list. No target URL, no baseline hash — both are handled at runtime.

```json
{
  "finding": "sql_injection",
  "parameter": "username",
  "payloads": [
    "' OR '1'='1",
    "' UNION SELECT 1,group_concat(username||':'||password),3,4 FROM users-- -",
    "' AND SLEEP(5)-- -"
  ]
}
```

**To test a different parameter a search field, an ID field, a password field  change `"parameter"` to match. The payloads and detection logic stay the same.**

---

## Payload Categories Covered

The included `config.json` ships with 33 payloads across 8 attack categories.

**Classic Auth Bypass** - OR-based tautologies and comment termination that short-circuit the WHERE clause entirely.

**Blind Boolean** - True/false condition pairs using `AND 1=1` vs `AND 1=2`. A differential response between the two confirms an active injection point via the **boolean-based blind SQLi** technique.

**Time-Based Blind** - SQLite `randomblob()` and MySQL `SLEEP()` payloads that force computational delay. Responses exceeding 4 seconds trigger a timing anomaly flag.

**Error-Based** - `EXTRACTVALUE()` and `UPDATEXML()` for MySQL; `CAST()` type mismatch for SQLite. Forces the database engine to surface data inside error messages.

**UNION-Based Extraction** - `UNION SELECT` payloads that piggyback a second query onto the original, dumping usernames, password hashes, emails, schema, and SQLite version in a single request.

**Encoding Bypass** - `hex()` and `char()` functions replace string literals entirely. Payloads like `char(97,100,109,105,110)` spell `admin` in ASCII - zero quotes used, defeating quote-based sanitizers.

**WAF Bypass** - Inline comment obfuscation (`UN/**/ION`), MySQL version-conditional comments (`/*!50000OR*/`), and tab-encoding (`%09`) break WAF keyword signatures while remaining valid SQL on the backend.

**Input Sanitization Specific** - Quote-doubling tautologies (`'' OR ''=''`), string concatenation (`'||'1'='1`), and `LIKE` operator substitution directly target sanitization logic rather than parameterization gaps.

---

## Output Explained

```
[TC-02] Payload: ' OR '1'='1' OR '1'='1
        Status : 200 | Time: 0.02s | Hash Match: NO
        Result : FAIL -- Status code change (401 → 200)
        Result : FAIL -- Hash deviation detected
        Risk   : SQL Injection confirmed -- multiple anomaly types detected

[TC-04] Payload: ' OR 1=2-- -
        Status : 401 | Time: 0.02s | Hash Match: YES
        Result : PASS
        Risk   : None -- payload had no effect on response
```

**FAIL** means the payload produced a measurable change in the application's response — status code shifted, response body changed, or response time spiked. The Risk line classifies severity based on how many anomaly types fired simultaneously.

**PASS** means the payload had zero effect — the application returned an identical response to the clean baseline. Against a properly fixed app using parameterized queries, all payloads return PASS because user input is bound as a typed value and never interpreted as SQL syntax.

---

## Risk Classification

| Anomalies Detected | Risk Line |
|---|---|
| Hash deviation only | `SQL Injection possible -- response body altered by payload` |
| Status code change only | `SQL Injection possible -- unexpected status code triggered` |
| Timing anomaly only | `SQL Injection possible -- time-based blind injection detected` |
| Two or more anomalies | `SQL Injection confirmed -- multiple anomaly types detected` |
| None | `None -- payload had no effect on response` |

---

## Evidence Output

Every run produces a timestamped JSON evidence file with a SHA-256 integrity hash.

```
[+] Evidence saved : evidence_20260318_003734.json
[+] SHA-256        : 1d8bc013...
```

The SHA-256 hash is computed over the entire report file - use it to verify the evidence has not been tampered with between capture and review.

---

## Disclaimer

This tool is built for authorised security testing and remediation verification only. Do not run against targets without explicit written permission.
