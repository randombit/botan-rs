#!/bin/sh

if [ "x$FEATURES" = "x" ]; then
    cargo build --verbose
    cargo test --verbose
else
    cd botan-sys
    cargo build --verbose
    cargo test --verbose
    cd ../botan
    cargo build --verbose --features "$FEATURES"
    cargo test --verbose --features "$FEATURES"
fi
