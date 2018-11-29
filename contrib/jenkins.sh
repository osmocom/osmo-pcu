#!/bin/sh
# jenkins build helper script for osmo-pcu.  This is how we build on jenkins.osmocom.org
#
# environment variables:
# * with_dsp: the DSP to configure ("sysmo", "lc15" or "none")
# * with_vty: enable VTY tests if set to "True"
# * WITH_MANUALS: build manual PDFs if set to "1"
# * PUBLISH: upload manuals after building if set to "1" (ignored without WITH_MANUALS = "1")
#

if ! [ -x "$(command -v osmo-build-dep.sh)" ]; then
	echo "Error: We need to have scripts/osmo-deps.sh from http://git.osmocom.org/osmo-ci/ in PATH !"
	exit 2
fi


set -ex

if [ -z "$MAKE" ]; then
  echo 'The $MAKE variable is not defined, cannot build'
  exit 1
fi

base="$PWD"
deps="$base/deps"
inst="$deps/install"
export deps inst

osmo-clean-workspace.sh

mkdir "$deps" || true

# Collect configure options for osmo-pcu
PCU_CONFIG=""
if [ "$with_dsp" = sysmo ]; then
  PCU_CONFIG="$PCU_CONFIG --enable-werror --enable-sysmocom-dsp --with-sysmobts=$inst/include/"

  # For direct sysmo DSP access, provide the SysmoBTS Layer 1 API
  cd "$deps"
  osmo-layer1-headers.sh sysmo
  mkdir -p "$inst/include/sysmocom/femtobts"
  ln -s $deps/layer1-headers/include/* "$inst/include/sysmocom/femtobts/"
  cd "$base"

elif [ "$with_dsp" = lc15 ]; then
  PCU_CONFIG="$PCU_CONFIG --enable-lc15bts-phy --with-litecell15=$deps/layer1-headers/inc"
  cd "$deps"
  osmo-layer1-headers.sh lc15 "$FIRMWARE_VERSION"
  cd "$base"

elif [ -z "$with_dsp" -o "$with_dsp" = none ]; then
  echo "Direct DSP access disabled, sanitizer enabled"
  PCU_CONFIG="$PCU_CONFIG --enable-werror --enable-sanitize"
else
  echo 'Invalid $with_dsp value:' $with_dsp
  exit 1
fi

if [ "$with_vty" = "True" ]; then
  PCU_CONFIG="$PCU_CONFIG --enable-vty-tests"
elif [ -z "$with_vty" -o "$with_vty" = "False" ]; then
  echo "VTY tests disabled"
else
  echo 'Invalid $with_vty value:' $with_vty
  exit 1
fi

verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

# Build deps
osmo-build-dep.sh libosmocore "" --disable-doxygen

export PKG_CONFIG_PATH="$inst/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$inst/lib"
export PATH="$inst/bin:$PATH"

if [ "$WITH_MANUALS" = "1" ]; then
  osmo-build-dep.sh osmo-gsm-manuals
  PCU_CONFIG="$PCU_CONFIG --enable-manuals"
fi

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
DISTCHECK_CONFIGURE_FLAGS="$PCU_CONFIG" \
  $MAKE distcheck \
  || cat-testlogs.sh

if [ "$WITH_MANUALS" = "1" ] && [ "$PUBLISH" = "1" ]; then
  make -C "$base/doc/manuals" publish
fi

osmo-clean-workspace.sh
