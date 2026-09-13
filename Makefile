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

# agent cross-compiles the Windows agent.
agent:
	GOOS=windows GOARCH=amd64 go build -trimpath -o bin/retune-agent.exe ./cmd/retune-agent

# msi builds the agent installer (requires the WiX 5 dotnet tool).
msi:
	pwsh deploy/msi/build.ps1
