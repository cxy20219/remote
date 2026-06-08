# Multi-stage Dockerfile for tunnel-rs-server.
#
# Stage 1 (`builder`): compiles the release binary with full static
# linking for the `x86_64-unknown-linux-musl` target. The resulting
# binary is ~3 MB and has no dependency on glibc / libssl / etc.
#
# Stage 2 (`runtime`): a `scratch` image carrying only the binary,
# `/etc/passwd` (so the binary can drop privileges), and `ca-certificates`
# (rustls may want to verify a server cert when --tls is enabled).
#
# Build:   docker build -t tunnel-rs-server:dev .
# Run:     docker run --rm -p 8080:8080 -v tunnel-rs-data:/data tunnel-rs-server:dev
# Inspect: docker exec ... cat /data/server-state.json

# ---------- Stage 1: builder ----------
FROM rust:1.85-alpine AS builder

# musl toolchain + the C bootstrap libraries the aws-lc-sys / ring
# crypto providers link against.
RUN apk add --no-cache musl-dev pkgconfig openssl-dev

WORKDIR /build

# Cache dependencies: copy manifests first so a source-only change
# doesn't bust the `cargo build` layer.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build the server release binary, fully static.
RUN cargo build --release \
        --target x86_64-unknown-linux-musl \
        -p tunnel-rs-server \
    && strip target/x86_64-unknown-linux-musl/release/tunnel-rs-server

# ---------- Stage 2: runtime ----------
FROM scratch

# OCI labels for image registry indexing.
LABEL org.opencontainers.image.title="tunnel-rs-server" \
      org.opencontainers.image.description="Approval-based reverse tunnel server (Rust port of go-remote)" \
      org.opencontainers.image.source="https://example.invalid/tunnel-rs" \
      org.opencontainers.image.licenses="MIT"

# We need `/etc/passwd` for the `tunnel` user (so axum's peer-address
# resolution doesn't need root) and `ca-certificates` for the rustls
# webpki-roots bundle when `--tls` is enabled.
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# The compiled, stripped, static binary (~3 MB).
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/tunnel-rs-server \
                    /usr/local/bin/tunnel-rs-server

# Run as a non-root user (uid 65532 is the conventional "nobody" for
# scratch / distroless images).
USER 65532:65532

# State directory — mount a volume here for persistence across restarts.
VOLUME ["/data"]
WORKDIR /data

# Defaults; override with `-e RUST_LOG=info` or `--env RUST_LOG_FORMAT=json`.
ENV RUST_LOG=info \
    RUST_LOG_FORMAT= \
    TUNNEL_RS_ADDR=0.0.0.0:8080 \
    TUNNEL_RS_DATA_DIR=/data

EXPOSE 8080

# Note: Docker HEALTHCHECK is omitted because `scratch` carries no
# `curl`/`wget`/shell. Use a sidecar (`docker-compose` with
# `wurstbrot/healthcheck` or similar) or `docker exec` to probe
# `/healthz` and `/readyz` from outside the container.

ENTRYPOINT ["/usr/local/bin/tunnel-rs-server"]
