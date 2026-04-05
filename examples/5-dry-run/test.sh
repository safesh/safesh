#!/bin/sh

FAIL=0
fail() { echo "FAIL: $*" >&2; FAIL=1; }

echo "Waiting for server..."
i=0
until curl -sf "$SERVER_URL/install.sh" > /dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -ge 15 ] && echo "ERROR: server did not start in time" >&2 && exit 1
    sleep 1
done

echo "Running: curl | safesh --dry-run --no-confirm"
OUTPUT=$(curl -fsSL "$SERVER_URL/install.sh" | safesh --dry-run --no-confirm 2>&1)
STATUS=$?
echo "$OUTPUT"

# dry-run must exit 0 (script not executed, so no failure from sudo/curl)
[ "$STATUS" -ne 0 ] && fail "expected exit 0 from dry-run, got $STATUS"

# Findings must be reported
echo "$OUTPUT" | grep -q "privilege"   || fail "expected [privilege] finding"
echo "$OUTPUT" | grep -q "network"     || fail "expected [network] finding"
echo "$OUTPUT" | grep -q "persistence" || fail "expected [persistence] finding"

# Script must NOT have been executed (the echo "Done." in install.sh would print to stdout)
echo "$OUTPUT" | grep -q "Done\." && fail "script was executed during dry-run"

[ "$FAIL" -eq 0 ] && echo "PASS" && exit 0
exit 1
