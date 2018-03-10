#!/bin/sh

set -ex

case $BUILD in
  stack)
    dpkg -L softhsm2
    dpkg -L libsofthsm2
    ldd /usr/lib/softhsm/libsofthsm2.so
    stack --version
    stack -v build --haddock
    stack test || true
    ldd .stack-work/install/x86_64-linux/lts-10.5/8.2.2/bin/pkcs11-tests
    ;;
  cabal)
    if [ -f configure.ac ]; then autoreconf -i; fi
    cabal configure -v2  # -v2 provides useful information for debugging
    cabal build   # this builds all libraries and executables (including tests/benchmarks)
    #cabal test (disabled, requires softhsm)
    cabal sdist   # tests that a source-distribution can be generated

    # Check that the resulting source distribution can be built & installed.
    # If there are no other `.tar.gz` files in `dist`, this can be even simpler:
    # `cabal install --force-reinstalls dist/*-*.tar.gz`
    SRC_TGZ=$(cabal info . | awk '{print $2;exit}').tar.gz &&
      (cd dist && cabal install --force-reinstalls "$SRC_TGZ")
    ;;
esac