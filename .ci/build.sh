#!/bin/sh

if [ "x$FEATURES" = "x" ]; then
    cargo build --verbose
    cargo test --verbose

    if [ "$TRAVIS_RUST_VERSION" = "nightly" ]; then
        cargo clippy
    fi

else
    cd botan-sys
    cargo build --verbose
    cargo test --verbose
    cd ../botan
    cargo build --verbose --features "$FEATURES"
    cargo test --verbose --features "$FEATURES"
fi
