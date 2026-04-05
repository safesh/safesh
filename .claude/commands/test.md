Run the test suite with race detection.

```sh
export PATH="$PATH:$(go env GOPATH)/bin"
task test
```

If you want coverage:
```sh
task test:cover
```
