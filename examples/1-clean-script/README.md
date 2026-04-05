# Example 1: Clean script

A script with no suspicious patterns. safesh analyzes it, reports no findings,
and runs it — exiting 0.

```
$ curl -fsSL https://example.com/install.sh | safesh --no-confirm
✓ no findings
note: a script with no findings is unsuspicious, not safe
Installing example app...
Done.
```

## Run

```sh
make test
```
