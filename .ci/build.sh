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

ccache --show-stats

if [ "x$FEATURES" == "xbotan3" ]; then
    git clone --depth 1 https://github.com/randombit/botan.git botan-git
    cd botan-git
    ./configure.py --compiler-cache=ccache
    make -j $(nproc) libs cli
    sudo make install
    cd ..
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

ccache --show-stats
