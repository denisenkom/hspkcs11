#!/bin/sh

set -ex

unset CC
export PATH=$HOME/.local/bin:/opt/ghc/$GHCVER/bin:/opt/cabal/$CABALVER/bin:$PATH
# Download and unpack the stack executable
mkdir -p ~/.local/bin
travis_retry curl -L https://www.stackage.org/stack/linux-x86_64 | tar xz --wildcards --strip-components=1 -C ~/.local/bin '*/stack'
