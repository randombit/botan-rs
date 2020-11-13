#!/bin/bash

set -ev

# deny all warnings in CI
export RUSTFLAGS="-D warnings"

if [ "x$FEATURES" != "xvendored" ]; then
    pushd /tmp

    git clone --branch release-2 --depth 1 https://github.com/randombit/botan.git

    cd botan
    CXX='ccache g++' ./configure.py --disable-static --without-documentation --with-debug-info
    make -j$(nproc) libs cli
    sudo make install
    sudo ldconfig

    popd
fi

if [ "x$FEATURES" = "x" ]; then
    cargo build --verbose
    cargo test --verbose -- --test-threads 4

    if [ "$TRAVIS_RUST_VERSION" = "nightly" ]; then
        cargo clippy
    fi

else
    cd botan-sys
    cargo build --verbose --features "$FEATURES"
    cargo test --verbose --features "$FEATURES" -- --test-threads 4
    cd ../botan
    cargo build --verbose --features "$FEATURES"
    cargo test --verbose --features "$FEATURES" -- --test-threads 4
fi
