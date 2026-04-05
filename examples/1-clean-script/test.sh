#!/bin/sh
set -e

FAIL=0
fail() { echo "FAIL: $*" >&2; FAIL=1; }

# Wait for the server to be ready
echo "Waiting for server..."
i=0
until curl -sf "$SERVER_URL/install.sh" > /dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -ge 15 ] && echo "ERROR: server did not start in time" >&2 && exit 1
    sleep 1
done

echo "Running: curl | safesh --no-confirm"
OUTPUT=$(curl -fsSL "$SERVER_URL/install.sh" | safesh --no-confirm 2>&1)
STATUS=$?
echo "$OUTPUT"

[ "$STATUS" -ne 0 ] && fail "expected exit 0, got $STATUS"
echo "$OUTPUT" | grep -q "no findings" || fail "expected 'no findings' in output"
echo "$OUTPUT" | grep -q "Done."       || fail "expected script output 'Done.'"

[ "$FAIL" -eq 0 ] && echo "PASS" && exit 0
exit 1
