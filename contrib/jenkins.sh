#!/usr/bin/env bash

set -ex

if [ -z "$MAKE" ]; then
  echo 'The $MAKE variable is not defined, cannot build'
  exit 1
fi

if [ $sysmobts = "no" -a $sysmodsp = "yes" ]; then
   echo "This config does not make sense."
   exit 0
fi

base="$PWD"
deps="$base/deps"
inst="$deps/install"

rm -rf "$inst"
mkdir "$deps" || true
cd "$deps"
osmo-deps.sh libosmocore

cd libosmocore
autoreconf --install --force
./configure --prefix="$inst"
$MAKE $PARALLEL_MAKE install

# Install the API
cd "$deps"
if ! test -d layer1-api;
then
  git clone git://git.sysmocom.de/sysmo-bts/layer1-api.git layer1-api
fi

cd layer1-api
git fetch origin
git reset --hard origin/master
api_incl="$inst/include/sysmocom/femtobts/"
mkdir -p "$api_incl"
cp include/*.h "$api_incl"

cd "$base"
autoreconf --install --force
BTS_CONFIG="--enable-sysmocom-bts=$sysmobts --enable-sysmocom-dsp=$sysmodsp"
if [ $sysmobts = "no" ]; then
  BTS_CONFIG="$BTS_CONFIG --enable-vty-tests"
fi

PKG_CONFIG_PATH="$inst/lib/pkgconfig" ./configure $BTS_CONFIG
PKG_CONFIG_PATH="$inst/lib/pkgconfig" $MAKE $PARALLEL_MAKE
DISTCHECK_CONFIGURE_FLAGS="$BTS_CONFIG" AM_DISTCHECK_CONFIGURE_FLAGS="$BTS_CONFIG" PKG_CONFIG_PATH="$inst/lib/pkgconfig" LD_LIBRARY_PATH="$inst/lib" $MAKE distcheck
