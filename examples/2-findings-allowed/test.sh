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

# --ci mode: findings are printed as warnings but execution proceeds.
# The script itself calls sudo which doesn't exist in the container, so
# safesh will exit non-zero (script failure) — but it must NOT exit because
# of findings alone. We capture output regardless of safesh exit code.
echo "Running: curl | safesh --ci"
OUTPUT=$(curl -fsSL "$SERVER_URL/install.sh" | safesh --ci 2>&1) || true
echo "$OUTPUT"

echo "$OUTPUT" | grep -q "privilege"  || fail "expected [privilege] finding"
echo "$OUTPUT" | grep -q "network"    || fail "expected [network] finding"
echo "$OUTPUT" | grep -q "proceeding" || fail "expected CI warning about proceeding"

[ "$FAIL" -eq 0 ] && echo "PASS" && exit 0
exit 1
