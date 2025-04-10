# syntax=docker/dockerfile:1

# === BUILD STAGE ===
FROM rust:1.86-slim AS builder

# Install only needed packages for bindgen + C compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    libclang-dev \
    llvm-dev \
    pkg-config \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set up workdir
WORKDIR /app

# Copy everything (make sure `.dockerignore` doesn’t exclude submodules if needed)
COPY . .

# Ensure submodules are initialized and updated
RUN git submodule update --init --recursive

# Add clippy and fmt tools
RUN rustup component add clippy rustfmt

# Add pre-checks for github build
RUN cargo fmt --all -- --check
RUN cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run tests to validate bindings
RUN cargo test --workspace --release --locked -- --nocapture
# Build the full workspace in release mode
RUN cargo build --release --workspace

# === RUNTIME STAGE ===
FROM debian:bookworm-slim

# Copy the final compiled binary
COPY --from=builder /app/target/release/cli /usr/local/bin/pqc-cli

# Use non-root user if needed for security
# USER nobody

# Set default command
ENTRYPOINT ["/usr/local/bin/pqc-cli"]
