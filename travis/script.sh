#!/bin/sh

set -ex

# configuring softhsm
conf_dir=$HOME/.config/softhsm2/
conf_path=$conf_dir/softhsm2.conf
var_path=$HOME/softhsmvar
mkdir -p $conf_dir
mkdir -p $var_path
echo directories.tokendir = $var_path > $conf_path
echo objectstore.backend = file >> $conf_path

case $BUILD in
  stack)
    #dpkg -L softhsm2
    #dpkg -L libsofthsm2
    #ldd /usr/lib/softhsm/libsofthsm2.so
    stack --version
    stack build --haddock --test
    #find .stack-work
    #ls -l .stack-work/dist/x86_64-linux/Cabal-2.0.1.0/build/pkcs11-tests/pkcs11-tests
    #ldd .stack-work/dist/x86_64-linux/Cabal-2.0.1.0/build/pkcs11-tests/pkcs11-tests
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