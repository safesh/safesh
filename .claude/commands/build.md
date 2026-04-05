Build the safesh binary to dist/safesh.

```sh
export PATH="$PATH:$(go env GOPATH)/bin"
task build
```

The binary is written to `dist/safesh`. Version is derived from `git describe`.
