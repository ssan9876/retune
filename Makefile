# Retune build helpers. On Windows, run the same commands by hand in PowerShell.
.PHONY: console build test test-go test-web clean

# console builds the admin console into the Go package that embeds it.
console:
	npm --prefix web ci
	npm --prefix web run build

build: console
	go build -o bin/ ./cmd/...

test: test-go test-web

test-go:
	go vet ./...
	go test ./...

test-web:
	npm --prefix web run test

clean:
	rm -rf bin internal/server/console/dist/assets internal/server/console/dist/index.html
