Run golangci-lint across the whole project.

```sh
export PATH="$PATH:$(go env GOPATH)/bin"
task lint
```

To auto-fix what's fixable:
```sh
task lint:fix
```
