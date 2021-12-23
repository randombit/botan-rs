#!/bin/bash

set -ex

# deny all warnings in CI
export RUSTFLAGS="-D warnings"
export CCACHE_MAXSIZE=2G
export BOTAN_CONFIGURE_COMPILER_CACHE=ccache
export INSTALL_PREFIX=/usr/local
export LD_LIBRARY_PATH=$INSTALL_PREFIX/lib
export DYLD_LIBRARY_PATH=$INSTALL_PREFIX/lib

FEATURES=$1

if [ "x$FEATURES" == "xvendored" ]; then
    git submodule update --init --depth 3
fi

if [ "x$FEATURES" = "x" ]; then
    cargo build
    cargo test
else
    cd botan-sys
    cargo build --features "$FEATURES"
    cargo test --features "$FEATURES"
    cd ../botan
    cargo build --features "$FEATURES"
    cargo test --features "$FEATURES"
fi
