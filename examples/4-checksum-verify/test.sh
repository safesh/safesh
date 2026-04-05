#!/bin/sh
set -e

FAIL=0
fail() { echo "FAIL: $*" >&2; FAIL=1; }

echo "Waiting for server..."
i=0
until curl -sf "$SERVER_URL/install.sh" > /dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -ge 15 ] && echo "ERROR: server did not start in time" >&2 && exit 1
    sleep 1
done

# Compute the expected SHA-256 of the served script at runtime
EXPECTED_HASH=$(curl -fsSL "$SERVER_URL/install.sh" | sha256sum | cut -d' ' -f1)
echo "Expected SHA-256: $EXPECTED_HASH"

# Run safesh in URL mode with the explicit hash — should verify and proceed
echo "Running: safesh --sha256 <hash> --no-confirm $SERVER_URL/install.sh"
OUTPUT=$(safesh --sha256 "$EXPECTED_HASH" --no-confirm "$SERVER_URL/install.sh" 2>&1)
STATUS=$?
echo "$OUTPUT"

[ "$STATUS" -ne 0 ]                          && fail "expected exit 0, got $STATUS"
echo "$OUTPUT" | grep -q "integrity verified" || fail "expected 'integrity verified' in output"
echo "$OUTPUT" | grep -q "All checks passed"  || fail "expected script output 'All checks passed'"

# Also verify that a wrong hash causes failure
echo "Running: safesh --sha256 deadbeef (wrong hash)"
BAD_OUTPUT=$(safesh --sha256 "deadbeefdeadbeef" --no-confirm "$SERVER_URL/install.sh" 2>&1 || true)
echo "$BAD_OUTPUT"
echo "$BAD_OUTPUT" | grep -q "integrity check FAILED" || fail "expected integrity failure with wrong hash"

[ "$FAIL" -eq 0 ] && echo "PASS" && exit 0
exit 1
