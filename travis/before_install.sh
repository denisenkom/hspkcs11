#!/bin/sh

set -ex

source travis_retry.sh

# Download and unpack the stack executable
mkdir -p ~/.local/bin
travis_retry curl -L https://www.stackage.org/stack/linux-x86_64 | tar xz --wildcards --strip-components=1 -C ~/.local/bin '*/stack'
