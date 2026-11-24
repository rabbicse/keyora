# For running the example without a local Rust toolchain.
#
# Build stage: Alpine's Rust targets musl, so the binary is statically linked
# and needs nothing from the runtime image. musl-dev provides the C runtime
# files the linker and the `ring` crypto crate need.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /app

# Compile the dependencies in their own layer: it is reused until Cargo.toml
# or Cargo.lock change.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release --locked

COPY src ./src
RUN touch src/main.rs && cargo build --release --locked

# Runtime stage: the binary and nothing else. No shell, no package manager.
# TLS root certificates are compiled into the binary (webpki-roots).
FROM scratch
COPY --from=build /app/target/release/keyora-example-axum /keyora-example-axum

# Inside a container the server must listen on all interfaces to be reachable
# through a published port.
ENV HOST=0.0.0.0 \
    PORT=9011

# An unprivileged numeric user ("nobody"); scratch has no /etc/passwd to name one.
USER 65534:65534
EXPOSE 9011
ENTRYPOINT ["/keyora-example-axum"]
