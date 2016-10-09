#!/usr/bin/env bash

set -ex

if [ -z "$MAKE" ]; then
  echo 'The $MAKE variable is not defined, cannot build'
  exit 1
fi

base="$PWD"
deps="$base/deps"
inst="$deps/install"
export deps inst

mkdir "$deps" || true
rm -rf "$inst"

# Collect configure options for osmo-pcu
PCU_CONFIG=""
if [ "$with_dsp" = sysmo ]; then
  PCU_CONFIG="$PCU_CONFIG --enable-sysmocom-dsp"

  # For direct sysmo DSP access, provide the SysmoBTS Layer 1 API
  cd "$deps"
  if [ ! -d layer1-api ]; then
    git clone git://git.sysmocom.de/sysmo-bts/layer1-api.git layer1-api
  fi
  cd layer1-api
  git fetch origin
  git reset --hard origin/master
  api_incl="$inst/include/sysmocom/femtobts/"
  mkdir -p "$api_incl"
  cp include/*.h "$api_incl"
  cd "$base"

elif [ -z "$with_dsp" -o "$with_dsp" = none ]; then
  echo "Direct DSP access disabled"
else
  echo 'Invalid $with_dsp value:' $with_dsp
  exit 1
fi

if [ "$with_vty" = "yes" ]; then
  PCU_CONFIG="$PCU_CONFIG --enable-vty-tests"
elif [ -z "$with_vty" -o "$with_vty" = "no" ]; then
  echo "VTY tests disabled"
else
  echo 'Invalid $with_vty value:' $with_vty
  exit 1
fi

# Build deps
osmo-build-dep.sh libosmocore

export PKG_CONFIG_PATH="$inst/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$inst/lib"

set +x
echo
echo
echo
echo " =============================== osmo-pcu ==============================="
echo
set -x

autoreconf --install --force
./configure $PCU_CONFIG
$MAKE $PARALLEL_MAKE
DISTCHECK_CONFIGURE_FLAGS="$PCU_CONFIG" AM_DISTCHECK_CONFIGURE_FLAGS="$PCU_CONFIG" \
  $MAKE distcheck \
  || cat-testlogs.sh
