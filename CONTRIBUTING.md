# Contributing

## Prerequisites

- Go 1.22+
- [Task](https://taskfile.dev) (`go install github.com/go-task/task/v3/cmd/task@latest`)
- golangci-lint (`go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`)

Ensure `$(go env GOPATH)/bin` is on your `PATH`.

## Build & test

```sh
task build    # build ./dist/safesh
task test     # go test -race ./...
task lint     # golangci-lint
task ci       # lint + test + build
task test-e2e # end-to-end examples
```

## Submitting changes

1. Fork the repo and create a branch from `main`.
2. Make your change with tests.
3. Run `task ci` — all checks must pass locally before opening a PR.
4. Open a pull request against `main`.

## Reporting security issues

See [SECURITY.md](SECURITY.md).
