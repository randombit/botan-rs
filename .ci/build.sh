#!/bin/bash

set -ex

# deny all warnings in CI
export RUSTFLAGS="-D warnings"
export CCACHE_MAXSIZE=2G
export BOTAN_CONFIGURE_COMPILER_CACHE=ccache

FEATURES=$1

if [ "x$FEATURES" != "xvendored" ]; then
    pushd /tmp

    git clone --branch release-2 --depth 1 https://github.com/randombit/botan.git

    cd botan
    ./configure.py --disable-static --without-documentation --compiler-cache=ccache
    ccache -s
    make -j$(nproc) libs cli
    ccache -s
    sudo make install
    sudo ldconfig

    popd
else
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
