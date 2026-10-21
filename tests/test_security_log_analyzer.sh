#!/usr/bin/env bash

set -u

PASS=0
FAIL=0

run_test() {
    local name="$1"
    local file="$2"
    local expected="$3"
    local output

    output=$(java SecurityLogAnalyzer.java "$file" 2>&1) || {
        echo "[FAIL] $name: analyzer exited with an error"
        FAIL=$((FAIL + 1))
        return
    }

    if grep -Fq "$expected" <<< "$output"; then
        echo "[PASS] $name"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $name"
        echo "  Expected to find: $expected"
        echo "  Actual output:"
        echo "$output"
        FAIL=$((FAIL + 1))
    fi
}

run_negative_test() {
    local name="$1"
    local file="$2"
    local unexpected="$3"
    local output

    output=$(java SecurityLogAnalyzer.java "$file" 2>&1) || {
        echo "[FAIL] $name: analyzer exited with an error"
        FAIL=$((FAIL + 1))
        return
    }

    if grep -Fq "$unexpected" <<< "$output"; then
        echo "[FAIL] $name: found unexpected output"
        echo "  Unexpected: $unexpected"
        FAIL=$((FAIL + 1))
    else
        echo "[PASS] $name"
        PASS=$((PASS + 1))
    fi
}

run_test "Normal activity parses 20 entries" \
    "data/reference-logs/normal_activity.log" \
    "Parsed 20 authentication entries."

run_test "Brute-force alert detects 19 failures" \
    "data/reference-logs/brute_force.log" \
    "[ALERT] 203.0.113.42: 19 failed attempts"

run_test "Username enumeration detects 18 usernames" \
    "data/reference-logs/username_enumeration.log" \
    "[ALERT] 198.51.100.77: 18 unique usernames"

run_test "Suspicious successful login is detected" \
    "data/reference-logs/suspicious_success.log" \
    "[ALERT] 203.0.113.88 successfully logged in as deploy after 11 failed attempts"

run_test "Distributed attack detects brute-force warnings" \
    "data/reference-logs/distributed_attack.log" \
    "[WARNING] 203.0.113.101: 6 failed attempts"

run_test "Mixed activity detects brute-force behavior" \
    "data/reference-logs/mixed_activity.log" \
    "[ALERT] 203.0.113.120: 11 failed attempts"

run_test "Edge cases skip malformed entries" \
    "data/reference-logs/edge_cases.log" \
    "Skipped 2 malformed authentication entries."

run_negative_test "Normal activity produces no alerts" \
    "data/reference-logs/normal_activity.log" \
    "[ALERT]"

run_negative_test "Nine failures do not trigger a brute-force alert" \
    "tests/fixtures/brute_force_9.log" \
    "[ALERT]"

run_test "Ten failures trigger a brute-force alert" \
    "tests/fixtures/brute_force_10.log" \
    "[ALERT] 203.0.113.201: 10 failed attempts"

run_negative_test "Four usernames produce no warning" \
    "tests/fixtures/username_enum_4.log" \
    "[WARNING]"

run_test "Five usernames trigger enumeration warning" \
    "tests/fixtures/username_enum_5.log" \
    "[WARNING] 203.0.113.203: 5 unique usernames"

run_negative_test "Failures outside the window do not trigger an alert" \
    "tests/fixtures/brute_force_outside_window.log" \
    "[ALERT]"

run_test "Attempts exactly 60 seconds apart trigger an alert" \
    "tests/fixtures/brute_force_exact_60_seconds.log" \
    "[ALERT] 203.0.113.205: 10 failed attempts"

run_negative_test "Different username does not trigger login-after-failures alert" \
    "tests/fixtures/success_different_username.log" \
    "successfully logged in as"

run_test "Empty log file is handled safely" \
    "tests/fixtures/empty_test.log" \
    "[INFO] The log file is empty."

run_test "Missing log file reports an error" \
    "data/reference-logs/does_not_exist.log" \
    "[ERROR] Could not read the log file: data/reference-logs/does_not_exist.log"

run_test "Distributed attack detects second IP" \
    "data/reference-logs/distributed_attack.log" \
    "[WARNING] 203.0.113.102: 6 failed attempts"

run_test "Distributed attack detects third IP" \
    "data/reference-logs/distributed_attack.log" \
    "[WARNING] 203.0.113.103: 6 failed attempts"

run_negative_test "Six failures do not trigger a brute-force alert" \
    "data/reference-logs/distributed_attack.log" \
    "[ALERT] 203.0.113.101: 6 failed attempts"

run_test "Mixed activity counts three unique usernames" \
    "data/reference-logs/mixed_activity.log" \
    "3 unique usernames"

run_negative_test "Three usernames do not trigger an enumeration warning" \
    "data/reference-logs/mixed_activity.log" \
    "[WARNING] 198.51.100.90:"

run_negative_test "Unrelated successful login does not trigger a login-after-failures alert" \
    "data/reference-logs/brute_force.log" \
    "successfully logged in as"

run_test "Suspicious login scenario also detects brute force" \
    "data/reference-logs/suspicious_success.log" \
    "[ALERT] 203.0.113.88: 11 failed attempts"

run_test "Repeated failures for one username count as one unique username" \
    "data/reference-logs/suspicious_success.log" \
    "1 unique usernames"

run_negative_test "Normal activity has no login-after-failures alert" \
    "data/reference-logs/normal_activity.log" \
    "successfully logged in as"

run_test "Combined dataset loads 140 lines" \
    "data/reference-logs/reference_auth.log" \
    "Loaded 140 log lines."

run_test "Combined dataset parses 132 authentication entries" \
    "data/reference-logs/reference_auth.log" \
    "Parsed 132 authentication entries."

run_test "Combined dataset ignores six non-authentication lines" \
    "data/reference-logs/reference_auth.log" \
    "Ignored 6 non-authentication lines."

run_test "Combined dataset skips two malformed entries" \
    "data/reference-logs/reference_auth.log" \
    "Skipped 2 malformed authentication entries."

run_test "Combined dataset detects 18 failures from enumeration IP" \
    "data/reference-logs/reference_auth.log" \
    "[ALERT] 198.51.100.77: 18 failed attempts"

run_test "Combined dataset detects 11 failures from mixed-activity IP" \
    "data/reference-logs/reference_auth.log" \
    "[ALERT] 203.0.113.120: 11 failed attempts"

run_test "Combined dataset detects 19 brute-force failures" \
    "data/reference-logs/reference_auth.log" \
    "[ALERT] 203.0.113.42: 19 failed attempts"

run_test "Combined dataset detects suspicious successful login" \
    "data/reference-logs/reference_auth.log" \
    "[ALERT] 203.0.113.88 successfully logged in as deploy after 11 failed attempts"

run_test "Combined dataset detects distributed attacker one" \
    "data/reference-logs/reference_auth.log" \
    "[WARNING] 203.0.113.101: 6 failed attempts"

run_test "Combined dataset detects distributed attacker two" \
    "data/reference-logs/reference_auth.log" \
    "[WARNING] 203.0.113.102: 6 failed attempts"

run_test "Combined dataset detects distributed attacker three" \
    "data/reference-logs/reference_auth.log" \
    "[WARNING] 203.0.113.103: 6 failed attempts"

run_test "Shuffled timestamps still detect brute-force activity" \
    "tests/fixtures/shuffled_timestamps.log" \
    "[ALERT] 203.0.113.150: 10 failed attempts within 60 seconds."

run_test "Identical timestamps still detect brute-force activity" \
    "tests/fixtures/identical_timestamps.log" \
    "[ALERT] 203.0.113.160: 10 failed attempts within 60 seconds."

run_negative_test "Successful logins alone do not trigger brute-force alerts" \
    "tests/fixtures/success_only.log" \
    "[ALERT]"

echo
echo "Results: $PASS passed, $FAIL failed."

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
