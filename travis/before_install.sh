#!/bin/sh

sudo apt-get -qq update

unset CC
export PATH=$HOME/.local/bin:/opt/ghc/$GHCVER/bin:/opt/cabal/$CABALVER/bin:$PATH
# Download and unpack the stack executable
mkdir -p ~/.local/bin
travis_retry curl -L https://www.stackage.org/stack/linux-x86_64 | tar xz --wildcards --strip-components=1 -C ~/.local/bin '*/stack'

# Download and build softhsm package
mkdir -p ~/.local/softhsm
cd ~/.local/softhsm
wget https://dist.opendnssec.org/source/softhsm-2.3.0.tar.gz
tar -xf softhsm-2.3.0.tar.gz
rm softhsm-2.3.0.tar.gz
cd softhsm-2.3.0
./configure --prefix=$HOME/.local/
make
cd ..
rm -r softhsm-2.3.0