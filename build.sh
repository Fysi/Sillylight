#!/bin/sh
# Cloudflare's build image has no Rust, so install it there before building the worker.
set -e
export PATH="$HOME/.cargo/bin:$PATH"
command -v cargo >/dev/null || curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
rustup target add wasm32-unknown-unknown
cargo install -q worker-build@^0.9
worker-build --release
