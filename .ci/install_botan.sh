#!/bin/sh

set -ev

cd /tmp

git clone --depth 1 https://github.com/randombit/botan.git

cd botan
CXX='ccache g++' CXXFLAGS=-O ./configure.py --disable-static --without-documentation --with-debug-info
make -j$(nproc) libs cli
sudo make install
sudo ldconfig
