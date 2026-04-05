# Example 3: Aborted run

A script containing an obfuscated `eval`+`base64` payload — a blocking finding
category. In non-interactive mode (e.g. CI, piped input) safesh refuses to run
it and exits non-zero. The script never executes.

```
$ curl -fsSL https://example.com/install.sh | safesh

  [obfuscation]  line 6  eval "$(echo '...' | base64 -d)"

warning: non-interactive mode — skipping confirmation, execution blocked
```

## Run

```sh
make test
```
