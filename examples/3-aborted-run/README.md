# Example 3: Aborted run

A script containing an obfuscated `eval`+`base64` payload — a blocking finding
category. In non-interactive mode (e.g. CI, piped input) safesh refuses to run
it and exits non-zero. The script never executes.

The same fixture also exercises the `homograph` module: a URL whose host has a
Cyrillic 'а' (U+0430) inside a Latin label, and a comment containing a U+202E
right-to-left override that flips the rendered filename.

```
$ curl -fsSL https://example.com/install.sh | safesh

  [obfuscation]  line 12  eval "$(echo '...' | base64 -d)"
  [homograph]    line 7   URL host "downloаds.example.com" mixes scripts …
  [homograph]    line 9   bidi control character U+202E RLO …

warning: non-interactive mode — skipping confirmation, execution blocked
```

## Run

```sh
make test
```
