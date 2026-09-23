# Retune build helpers. On Windows, run the same commands by hand in PowerShell.
.PHONY: console build test test-go test-web clean docker compose-up compose-down msi agent

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

# docker builds the server image. The repository root is the build context
# because the image builds the console from web/ as well as the Go binary.
docker:
	docker build -f deploy/docker/Dockerfile -t retune-server:dev .

compose-up:
	docker compose -f deploy/docker/docker-compose.yml up --build -d

compose-down:
	docker compose -f deploy/docker/docker-compose.yml down

# agent cross-compiles the Windows agent. VERSION stamps the binary; an
# unstamped build refuses to self-update, on purpose. RELEASE_KEY (a path, or
# env:NAME) signs the build and stamps its own public key as the trust list;
# RELEASE_PUBKEYS overrides the trust list for a rotation. Without RELEASE_KEY
# the build is unsigned, trusts nothing, and says so. OPERATIONS_PUBKEYS makes
# the agent require an operations signature on every script and wipe it runs.
VERSION ?= 0.1.0-dev
RELEASE_KEY ?=
RELEASE_PUBKEYS ?=
OPERATIONS_PUBKEYS ?=
agent:
	@if [ -n "$(RELEASE_KEY)" ] && [ -z "$(RELEASE_PUBKEYS)" ]; then \
	  echo "RELEASE_KEY is set; RELEASE_PUBKEYS must name the public key(s) to embed"; exit 1; fi
	GOOS=windows GOARCH=amd64 go build -trimpath \
	  -ldflags "-X retune/internal/agent/facts.AgentVersion=$(VERSION) -X retune/internal/agent/facts.TrustedKeysRaw=$(RELEASE_PUBKEYS) -X retune/internal/agent/facts.OperationsKeysRaw=$(OPERATIONS_PUBKEYS)" \
	  -o bin/retune-agent.exe ./cmd/retune-agent
	@if [ -n "$(RELEASE_KEY)" ]; then \
	  go run ./cmd/retune-sign sign --key "$(RELEASE_KEY)" --version "$(VERSION)" bin/retune-agent.exe; \
	else echo "bin/retune-agent.exe is unsigned and trusts no release key (set RELEASE_KEY and RELEASE_PUBKEYS)"; fi

# msi builds the agent installer (requires the WiX 5 dotnet tool).
msi:
	pwsh deploy/msi/build.ps1
