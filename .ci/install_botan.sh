#!/bin/sh

cd /tmp

git clone --depth 1 https://github.com/randombit/botan.git

cd botan
CXX='ccache g++' CXXFLAGS=-O ./configure.py --disable-static --without-documentation --with-debug-info
make -j3 libs cli
sudo make install
sudo ldconfig
