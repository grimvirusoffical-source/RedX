# Contributing

## Requirements

* Go 1.22 or newer.
* Node.js 18 or newer and Python 3.9 or newer, only to run the SDK tests.

## Build and test

```sh
go build ./...
go vet ./...
go test -race -count=1 ./...
```

SDK tests start a real `redxd` on a loopback port with a temporary data directory:

```sh
cd sdk/js && npm test
cd sdk/python && python3 -m unittest discover -s tests -t .
```

Release archives and a smoke test of the built binaries:

```sh
VERSION=0.3.0 scripts/build.sh
scripts/smoke.sh bin
scripts/cluster-smoke.sh bin
```

## Project layout

| Path | Contents |
|---|---|
| `box/` | Box grammar lexer, parser and writer |
| `engine/` | storage engines and subsystems (`query`, `idx`, `pack`, `media`, `sec`, `code`, `link`, `pulse`) |
| `host/` | the `redxd` server, key store, cluster and engine adapter |
| `cmd/redx`, `cmd/redxd` | command-line client and host |
| `sdk/` | JavaScript and Python clients |
| `deploy/` | installers, service definitions, Docker files |
| `docs/` | documentation |

## Guidelines

* Keep changes focused and include tests. Bug fixes should include a test that fails without the fix.
* Run `gofmt` and `go vet` before submitting.
* Documentation examples in `boxql` code blocks are parsed by the test suite, so they must stay valid.
* Do not commit key files, `.env` files, data directories or build output (`dist/`, `bin/`).
* Use clear commit messages in the imperative mood, for example `Fix follower write forwarding`.
