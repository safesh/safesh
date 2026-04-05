# Example 2: Findings allowed (CI mode)

A script with `privilege` and `network` findings. Running with `--ci` prints
findings as warnings but does not block — exit code reflects the script's own
outcome, not the presence of findings.

```
$ curl -fsSL https://example.com/install.sh | safesh --ci

  [privilege]  line 7   sudo apt-get install -y build-essential
  [network]    line 10  curl https://releases.example.com/v2.1.0/binary

warning: safesh --ci: 2 finding(s) reported above; proceeding with execution
```

## Run

```sh
make test
```
