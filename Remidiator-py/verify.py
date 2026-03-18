"""
verify.py — Remediation Verification Script
Finding : Accepts any finding type via JSON config
Part D  : Implementation Sprint

Usage:
    python verify.py config.json --target http://localhost:5000/api/v1/login
    python verify.py config.json --target http://localhost:5001/api/v1/login
    python verify.py config.json --target https://httpbin.org/post

No manual baseline hash needed — computed automatically at runtime.
No config editing needed to switch targets — pass via --target flag.
"""

import requests
import hashlib
import json
import sys
import time
import argparse
from datetime import datetime, timezone

# ------------------------------------------------------------------
# CONSTANTS
# ------------------------------------------------------------------
TIMING_THRESHOLD = 4.0    # seconds — above this is a timing anomaly
REQUEST_TIMEOUT  = 10.0   # seconds — max wait before giving up
BASELINE_SAMPLES = 2      # number of clean requests to average for baseline

# ------------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------------
def hash_body(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def load_config(path: str) -> dict:
    """Load and validate config.json."""
    try:
        with open(path) as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"[!] Config file not found: {path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON in config: {e}")
        sys.exit(1)

    # Validate required fields
    required = ["finding", "parameter", "payloads"]
    missing  = [f for f in required if f not in config]
    if missing:
        print(f"[!] Missing required fields in config: {missing}")
        sys.exit(1)

    if not isinstance(config["payloads"], list) or len(config["payloads"]) == 0:
        print(f"[!] Payloads must be a non-empty list")
        sys.exit(1)

    return config

def check_target(target: str, parameter: str) -> None:
    """Verify target is reachable before running tests."""
    print(f"[*] Checking target reachability...")
    try:
        resp = requests.post(
            target,
            data={parameter: ""},
            timeout=REQUEST_TIMEOUT
        )
        print(f"    Target reachable — Status: {resp.status_code} ✓\n")
    except requests.ConnectionError:
        print(f"[!] Cannot reach target: {target}")
        print(f"    Is the app running? Check the URL and try again.")
        sys.exit(1)
    except requests.Timeout:
        print(f"[!] Target timed out: {target}")
        sys.exit(1)

def compute_baseline(target: str, parameter: str) -> dict:
    """
    Send clean requests to establish live baseline.
    Averages BASELINE_SAMPLES requests to reduce jitter.
    No manual hash needed — computed fresh every run.
    """
    print(f"[*] Computing baseline ({BASELINE_SAMPLES} samples)...")
    times    = []
    last_resp = None

    for i in range(BASELINE_SAMPLES):
        t0   = time.perf_counter()
        resp = requests.post(
            target,
            data={parameter: ""},
            timeout=REQUEST_TIMEOUT
        )
        elapsed = time.perf_counter() - t0
        times.append(elapsed)
        last_resp = resp

    baseline = {
        "status" : last_resp.status_code,
        "hash"   : hash_body(last_resp.text),
        "latency": round(sum(times) / len(times), 3)
    }

    print(f"    Status  : {baseline['status']}")
    print(f"    Hash    : {baseline['hash'][:16]}...")
    print(f"    Latency : {baseline['latency']}s")
    print(f"    Samples : {BASELINE_SAMPLES}\n")

    return baseline

def get_risk_line(anomalies: list[str]) -> str:
    """Generate risk assessment based on anomaly types detected."""
    if not anomalies:
        return "None -- payload had no effect on response"

    anomaly_text = " ".join(anomalies)

    if len(anomalies) >= 2:
        return "SQL Injection confirmed -- multiple anomaly types detected"
    elif "Timing" in anomaly_text:
        return "SQL Injection possible -- time-based blind injection detected"
    elif "Status" in anomaly_text:
        return "SQL Injection possible -- unexpected status code triggered by payload"
    elif "Hash" in anomaly_text:
        return "SQL Injection possible -- response body altered by payload"
    return "Unknown anomaly detected"

# ------------------------------------------------------------------
# CORE RUNNER
# ------------------------------------------------------------------
def run_verification(config: dict, target: str) -> dict:
    finding   = config["finding"]
    parameter = config["parameter"]
    payloads  = config["payloads"]
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Pre-flight checks
    check_target(target, parameter)
    baseline = compute_baseline(target, parameter)

    # Header
    print(f"===== REMEDIATION VERIFICATION REPORT =====")
    print(f"Finding  : {finding}")
    print(f"Target   : {target}")
    print(f"Timestamp: {timestamp}")
    print(f"Payloads : {len(payloads)} test cases")
    print()

    results = []
    failed  = 0
    passed  = 0

    for i, payload in enumerate(payloads, start=1):
        tc_id  = f"TC-{i:02d}"
        result = {
            "id"           : tc_id,
            "payload"      : payload,
            "status_code"  : None,
            "response_time": None,
            "hash_match"   : None,
            "anomalies"    : [],
            "verdict"      : None,
            "error"        : None
        }

        try:
            t0   = time.perf_counter()
            resp = requests.post(
                target,
                data={parameter: payload},
                timeout=TIMING_THRESHOLD + REQUEST_TIMEOUT
            )
            elapsed = time.perf_counter() - t0

            body_hash              = hash_body(resp.text)
            result["status_code"]  = resp.status_code
            result["response_time"]= round(elapsed, 2)
            result["hash_match"]   = body_hash == baseline["hash"]

            # Anomaly detection
            if resp.status_code != baseline["status"]:
                result["anomalies"].append(
                    f"Status code change ({baseline['status']} → {resp.status_code})"
                )
            if not result["hash_match"]:
                result["anomalies"].append("Hash deviation detected")

            adjusted = elapsed - baseline["latency"]
            if adjusted > TIMING_THRESHOLD:
                result["anomalies"].append(
                    f"Timing anomaly ({round(adjusted,2)}s > {TIMING_THRESHOLD}s threshold)"
                )

        except requests.Timeout:
            result["anomalies"].append(
                f"Timing anomaly (timeout > {TIMING_THRESHOLD}s threshold)"
            )
            result["error"]        = "Request timed out"
            result["response_time"]= TIMING_THRESHOLD
            result["hash_match"]   = False
            result["status_code"]  = "TIMEOUT"

        except requests.RequestException as e:
            result["error"]  = str(e)
            result["verdict"]= "ERROR"
            print(f"[{tc_id}] ERROR: {e}\n")
            results.append(result)
            continue

        # Verdict
        result["verdict"] = "FAIL" if result["anomalies"] else "PASS"
        if result["verdict"] == "FAIL":
            failed += 1
        else:
            passed += 1

        # Print result
        hash_str = "YES" if result["hash_match"] else "NO"
        time_str = f"{result['response_time']}s"
        risk     = get_risk_line(result["anomalies"])

        print(f"[{tc_id}] Payload: {payload}")
        print(f"        Status : {result['status_code']} | Time: {time_str} | Hash Match: {hash_str}")

        if result["verdict"] == "FAIL":
            for anomaly in result["anomalies"]:
                print(f"        Result : FAIL -- {anomaly}")
        else:
            print(f"        Result : PASS")

        print(f"        Risk   : {risk}")
        print()

        results.append(result)

    # Final verdict
    print(f"===== VERDICT: ", end="")
    if failed == 0:
        print(f"REMEDIATION SUCCESSFUL ✓ =====")
    else:
        print(f"REMEDIATION FAILED ✗ =====")
    print(f"Failed Tests : {failed} / {len(payloads)}")
    print(f"Passed Tests : {passed} / {len(payloads)}")
    print()

    return {
        "finding"  : finding,
        "target"   : target,
        "timestamp": timestamp,
        "baseline" : baseline,
        "summary"  : {
            "total" : len(payloads),
            "passed": passed,
            "failed": failed
        },
        "verdict"  : "REMEDIATION FAILED" if failed > 0 else "REMEDIATION SUCCESSFUL",
        "results"  : results
    }

# ------------------------------------------------------------------
# BONUS — Save timestamped JSON evidence + SHA-256
# ------------------------------------------------------------------
def save_evidence(report: dict) -> None:
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"evidence_{ts}.json"

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    file_hash = hashlib.sha256(open(filename, "rb").read()).hexdigest()
    print(f"[+] Evidence saved : {filename}")
    print(f"[+] SHA-256        : {file_hash}\n")

# ------------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SQLi Remediation Verification Tool",
        epilog="Example: python verify.py config.json --target http://localhost:5000/api/v1/login"
    )
    parser.add_argument("config",   help="Path to config JSON file")
    parser.add_argument("--target", required=True, help="Target URL to test against")
    args = parser.parse_args()

    config = load_config(args.config)
    report = run_verification(config, args.target)
    save_evidence(report)