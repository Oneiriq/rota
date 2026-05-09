# syntax=docker/dockerfile:1.7

# Multi-stage rust build for the rota workspace. Produces a slim
# distroless runtime image with both rotad (daemon) and rota (CLI)
# binaries. No shell in the runtime layer; operators talk to a
# running container via `docker exec rota /usr/local/bin/rota ...`.

FROM rust:1.90-slim-bookworm AS build
WORKDIR /src

# System libs the rust toolchain links against: rcgen, ring, rustls,
# instant-acme, pem, x509-parser, sqlite, oneiriq-surql.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       pkg-config \
       libssl-dev \
       ca-certificates \
       clang \
       cmake \
       protobuf-compiler \
       libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# Workspace manifests + source. Cargo.lock is committed so --locked
# gives a reproducible build.
COPY rust-toolchain.toml ./
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build both binaries in release mode against the pinned toolchain.
RUN cargo build --release --locked --bin rotad --bin rota
RUN strip target/release/rotad target/release/rota || true

# Runtime stage. Distroless cc gives glibc + ca-certs without a shell;
# rotad opens a UNIX socket + an HTTP listener and talks to remote
# CAs / DCV providers, so cc is the right base. Default user is root,
# which keeps file-mode 0600 mounts (config + per-cert keys) readable
# without UID-mapping gymnastics.
FROM gcr.io/distroless/cc-debian12
COPY --from=build /src/target/release/rotad /usr/local/bin/rotad
COPY --from=build /src/target/release/rota /usr/local/bin/rota

# Default config path. Operators bind-mount their rota.yaml here.
ENTRYPOINT ["/usr/local/bin/rotad"]
CMD ["--config", "/etc/rota/rota.yaml"]

# Dashboard / metrics HTTP listener. UNIX control socket lives at
# /var/run/rota.sock (or whatever rota.yaml configures); operators
# bind-mount the socket directory if they want host-side `rota` CLI
# access without `docker exec`.
EXPOSE 7878
