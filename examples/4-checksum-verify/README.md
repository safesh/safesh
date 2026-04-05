# Example 4: Checksum verification

safesh verifies the script's SHA-256 hash before running it. A mismatch aborts
execution before any analysis or prompt.

```
$ safesh --sha256 <expected-hash> --no-confirm https://example.com/install.sh
✓ integrity verified
Installing verified app...
All checks passed.
```

The test also demonstrates that a wrong hash causes an immediate failure:

```
$ safesh --sha256 deadbeef --no-confirm https://example.com/install.sh
✗ integrity check FAILED: expected deadbeef got <actual>
```

## Run

```sh
make test
```
