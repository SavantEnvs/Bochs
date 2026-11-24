#!/usr/bin/env bash
# mayhem/build.sh — Bochs fuzz targets + test tools.
#  * build/fuzz : the whole emulator (bochs) configured with afl-clang-fast and
#    ASan+UBSan — file-input AFL targets (fuzz input = guest ROM image).
#  * hdimage_fuzz: disk-image driver over iodev/hdimage (-DBXIMAGE, like bximage), AFL.
#  * vnet_fuzz / disasm_fuzz / slirp_fuzz: libFuzzer harnesses (+ -standalone reproducers).
#  * build/test : a NORMAL (unsanitized) build of bximage + bxdisasm for test.sh.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"
S="$SRC/bochs"
B="$SRC/mayhem/build"
OUT="$SRC/mayhem/out"
mkdir -p "$B/fuzz" "$B/test" "$B/obj" "$OUT"

CONF_OPTS=(--with-nogui --disable-plugins --enable-x86-64 --enable-pci
  --enable-usb --enable-usb-ohci --enable-usb-ehci --enable-usb-xhci
  --enable-e1000 --enable-ne2000 --enable-pnic --enable-clgd54xx --enable-voodoo
  --enable-cdrom --enable-sb16 --enable-es1370 --disable-docbook)

# 1) the emulator, AFL-instrumented, ASan+UBSan halting.
# Two UBSan checks are relaxed for the emulator ONLY, because upstream trips them
# on every run before/after any guest code executes: `bool` (gui/paramtree.cc
# bx_shadow_bool_c reads still-uninitialized bool members while the param tree is
# built) and `vptr` (iodev/devices.cc ~bx_devices_c calls bx_hdimage_ctl.exit()
# after that static was destroyed, at process exit) and `float-cast-overflow`
# (iodev/cmos.cc:366 periodic_interval_usec cast of a long-double NaN during CMOS
# reset in this build) and `alignment` (guest memory is accessed unaligned by
# design: misc/bswap.h ReadHostDWordFromLittleEndian on every instruction fetch).
# Everything else halts.
FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1"
EMU_FLAGS="$FLAGS"
[ -z "$SANITIZER_FLAGS" ] || EMU_FLAGS="$FLAGS -fno-sanitize=bool,vptr,float-cast-overflow,alignment"
# LSan off for every ASan binary (linked via LDFLAGS into bochs)
AFL_QUIET=1 afl-clang-fast++ $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/obj/lsan_off_afl.o"
cd "$B/fuzz"
if [ ! -f config.status ]; then
  CC=afl-clang-fast CXX=afl-clang-fast++ CFLAGS="$EMU_FLAGS" CXXFLAGS="$EMU_FLAGS" \
    LDFLAGS="$SANITIZER_FLAGS $B/obj/lsan_off_afl.o" "$S/configure" "${CONF_OPTS[@]}"
fi
AFL_QUIET=1 make -j"$MAYHEM_JOBS" bochs
cp -f bochs "$OUT/bochs"

INC=(-I"$B/fuzz" -I"$S" -I"$S/instrument/stubs")

# 2) disk-image driver (AFL file-input), sources compiled like the bximage rule
HD_OBJS=()
for f in hdimage_fuzz:mayhem/harnesses hdimage:bochs/iodev/hdimage vmware3:bochs/iodev/hdimage \
         vmware4:bochs/iodev/hdimage vpc:bochs/iodev/hdimage vhdx:bochs/iodev/hdimage \
         crc32c:bochs/iodev/hdimage vbox:bochs/iodev/hdimage; do
  n=${f%%:*}; d=${f#*:}; extra=
  # vpc.cc:226 casts the 512-byte HEADER_SIZE buffer to the 1024-byte
  # vhd_dyndisk_header_t, so UBSan's object-size check fires on every dynamic
  # VHD, valid ones included (upstream defect, reported in the PR). Relaxed on
  # this one file only; ASan still catches any real out-of-bounds read.
  [ "$n" != vpc ] || [ -z "$SANITIZER_FLAGS" ] || extra=-fno-sanitize=object-size
  AFL_QUIET=1 afl-clang-fast++ $FLAGS $extra -DBXIMAGE "${INC[@]}" -c "$SRC/$d/$n.cc" -o "$B/obj/hd-$n.o"
  HD_OBJS+=("$B/obj/hd-$n.o")
done
AFL_QUIET=1 afl-clang-fast++ $FLAGS "${HD_OBJS[@]}" "$B/obj/lsan_off_afl.o" -o "$OUT/hdimage_fuzz"

# 3) libFuzzer harnesses
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/obj/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/obj/lsan_off.o"
build_lf() {  # name harness sources... (defines in DEFS; FILE_FLAGS_<basename> adds per-file flags)
  local name=$1 harness=$2; shift 2
  local objs=()
  for src in "$harness" "$@"; do
    local bn; bn=$(basename "$src" .cc)
    local o="$B/obj/$name-$bn.o" ff="FILE_FLAGS_$bn"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link $DEFS ${!ff:-} "${INC[@]}" -c "$src" -o "$o"
    objs+=("$o")
  done
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${objs[@]}" "$B/obj/lsan_off.o" -o "$OUT/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/obj/standalone_main.o" "${objs[@]}" "$B/obj/lsan_off.o" -o "$OUT/$name-standalone"
}
DEFS=-DBXHUB build_lf vnet_fuzz "$SRC/mayhem/harnesses/vnet_fuzz.cc" "$S/iodev/network/netutil.cc"
# The decoder fetches immediates/displacements with unaligned loads by design
# (misc/bswap.h ReadHostWordFromLittleEndian), so UBSan `alignment` is relaxed here too.
DECODER_DEFS=-DBX_STANDALONE_DECODER
[ -z "$SANITIZER_FLAGS" ] || DECODER_DEFS="$DECODER_DEFS -fno-sanitize=alignment"
DEFS="$DECODER_DEFS" build_lf disasm_fuzz "$SRC/mayhem/harnesses/disasm_fuzz.cc" "$S"/cpu/decoder/*.cc
# Bundled slirp stack (iodev/network/slirp). Relaxed UBSan checks, slirp objects only:
#  * `alignment`: slirp parses IP/TCP headers in place right after the 14-byte
#    Ethernet header, so every TCP segment trips it (tcp_input.cc:265 struct qlink);
#  * `vptr`: the only virtual calls are through slirp.cc's logfunctions pointer,
#    which stays NULL (the check would also drag in the emulator's logio typeinfo);
#  * `pointer-overflow` on ip_input.cc only: ip_reass() computes
#    container_of(q, ...) before checking q, and q is NULL for the first fragment
#    of every datagram, valid ones included (upstream defect, reported in the PR).
# ASan stays on for all of it.
SLIRP_DEFS=
[ -z "$SANITIZER_FLAGS" ] || { SLIRP_DEFS="-fno-sanitize=vptr,alignment"; FILE_FLAGS_ip_input="-fno-sanitize=pointer-overflow"; }
DEFS="$SLIRP_DEFS" build_lf slirp_fuzz "$SRC/mayhem/harnesses/slirp_fuzz.cc" "$S"/iodev/network/slirp/*.cc
unset FILE_FLAGS_ip_input

# 4) test tools with NORMAL flags (no sanitizers): bximage + bxdisasm
cd "$B/test"
if [ ! -f config.status ]; then
  env -u CFLAGS -u CXXFLAGS -u LDFLAGS CFLAGS="-O2 $COVERAGE_FLAGS" CXXFLAGS="-O2 $COVERAGE_FLAGS" \
    LDFLAGS="$COVERAGE_FLAGS" "$S/configure" "${CONF_OPTS[@]}"
fi
make -j"$MAYHEM_JOBS" bximage
$CXX -O2 $COVERAGE_FLAGS -DBX_STANDALONE_DECODER -I"$B/test" -I"$S" -I"$S/instrument/stubs" \
  "$S/bxdisasm.cc" "$S"/cpu/decoder/*.cc -o "$B/test/bxdisasm"
echo "build.sh: done"
