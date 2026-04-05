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

# --ci mode: findings are printed as warnings but execution proceeds
echo "Running: curl | safesh --ci"
OUTPUT=$(curl -fsSL "$SERVER_URL/install.sh" | safesh --ci 2>&1)
STATUS=$?
echo "$OUTPUT"

# Script calls sudo which doesn't exist in the container, so exit code will be
# non-zero from the script itself — but safesh should NOT exit non-zero due to
# findings alone. Test that findings were reported as warnings.
echo "$OUTPUT" | grep -q "privilege"  || fail "expected [privilege] finding"
echo "$OUTPUT" | grep -q "network"    || fail "expected [network] finding"
echo "$OUTPUT" | grep -q "proceeding" || fail "expected CI warning about proceeding"

[ "$FAIL" -eq 0 ] && echo "PASS" && exit 0
exit 1
