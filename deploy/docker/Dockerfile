# syntax=docker/dockerfile:1

# Built with the repository root as the context, because the server binary
# embeds the console and so needs both web/ and the Go module.

# The console is built first: the Go binary embeds it with go:embed, and the
# built assets are gitignored. Skipping this stage would produce a server whose
# console is a 503 page rather than a build failure.
# The console and the binary are built on the build machine's own platform and
# cross-compiled, so an arm64 image doesn't run npm and the compiler emulated.
FROM --platform=$BUILDPLATFORM node:24-alpine AS console
WORKDIR /src
COPY web/package.json web/package-lock.json ./web/
RUN npm --prefix web ci
COPY web ./web
RUN npm --prefix web run build

FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=console /src/internal/server/console/dist ./internal/server/console/dist
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /out/retune-server ./cmd/retune-server
# Created here so a freshly created named volume inherits this ownership and
# the non-root process can write the CA key on first start.
RUN mkdir -p /out/data && chown 65532:65532 /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/retune-server /retune-server
COPY --from=build --chown=65532:65532 /out/data /var/lib/retune
USER nonroot
EXPOSE 8443
ENTRYPOINT ["/retune-server"]
CMD ["serve"]
