# Example 5: Dry run

`--dry-run` performs full analysis and reports all findings, but never executes
the script. Exit code is always 0 (analysis succeeded; no execution failure is
possible).

```
$ curl -fsSL https://example.com/install.sh | safesh --dry-run --no-confirm

  [privilege]    line 6   sudo apt-get install -y build-essential
  [persistence]  line 9   echo '...' >> ~/.bashrc
  [network]      line 12  curl https://releases.example.com/v2.1.0/binary

note: a script with no findings is unsuspicious, not safe
```

## Run

```sh
make test
```
