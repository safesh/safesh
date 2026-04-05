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

# No --no-confirm and no tty → non-interactive mode blocks on obfuscation finding
echo "Running: curl | safesh  (no --no-confirm)"
OUTPUT=$(curl -fsSL "$SERVER_URL/install.sh" | safesh 2>&1)
STATUS=$?
echo "$OUTPUT"

# safesh must exit non-zero and report that execution was blocked
[ "$STATUS" -eq 0 ] && fail "expected non-zero exit, got 0"
echo "$OUTPUT" | grep -q "obfuscation"      || fail "expected [obfuscation] finding"
echo "$OUTPUT" | grep -q "execution blocked" || fail "expected 'execution blocked' message"

[ "$FAIL" -eq 0 ] && echo "PASS" && exit 0
exit 1
