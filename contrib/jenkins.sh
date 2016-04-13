#!/usr/bin/env bash

set -ex

if [ $sysmobts = "no" -a $sysmodsp = "yes" ]; then
   echo "This config does not make sense."
   exit 0
fi

rm -rf deps/install
mkdir deps || true
cd deps
osmo-deps.sh libosmocore

cd libosmocore
autoreconf --install --force
./configure --prefix=$PWD/../install
$MAKE $PARALLEL_MAKE install

# Install the API
cd ../
if ! test -d layer1-api;
then
  git clone git://git.sysmocom.de/sysmo-bts/layer1-api.git layer1-api
fi

cd layer1-api
git fetch origin
git reset --hard origin/master
mkdir -p $PWD/../install/include/sysmocom/femtobts/
cp include/*.h ../install/include/sysmocom/femtobts/

cd ../../
autoreconf --install --force
BTS_CONFIG="--enable-sysmocom-bts=$sysmobts --enable-sysmocom-dsp=$sysmodsp"
if [ $sysmobts = "no" ]; then
  BTS_CONFIG="$BTS_CONFIG --enable-vty-tests"
fi

PKG_CONFIG_PATH=$PWD/deps/install/lib/pkgconfig ./configure $BTS_CONFIG
PKG_CONFIG_PATH=$PWD/deps/install/lib/pkgconfig $MAKE $PARALLEL_MAKE
DISTCHECK_CONFIGURE_FLAGS="$BTS_CONFIG" AM_DISTCHECK_CONFIGURE_FLAGS="$BTS_CONFIG" PKG_CONFIG_PATH=$PWD/deps/install/lib/pkgconfig LD_LIBRARY_PATH=$PWD/deps/install/lib $MAKE distcheck
