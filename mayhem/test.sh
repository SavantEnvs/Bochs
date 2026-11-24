#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# EDIT: RUN the test runner that mayhem/build.sh produced, then map its output to counts.
#   ctest:        (cd build-tests && ctest) ; parse "<P> tests passed, <F> failed out of <T>"
#   gtest binary: ./build-tests/<prog> ; parse "[==========] N ... ran." / "[  PASSED  ] P" / "[ SKIPPED ] S"
#   make/minunit: ./out/<runner> ; parse its pass/fail/total
# Do NOT compile here — if the runner is absent, fail (build.sh should have produced it).

# Known-answer tests over the NORMAL (unsanitized) bximage + bxdisasm that
# build.sh left in mayhem/build/test:
#  * image round trips: a flat image with marker bytes is converted to each
#    writable format, `bximage -func=info` must detect that format, and the
#    image converted back to flat must be byte-identical to the original.
#  * disassembler: known instruction bytes must decode to known mnemonics.
T="$SRC/mayhem/build/test"
BX="$T/bximage"; DIS="$T/bxdisasm"
[ -x "$BX" ] && [ -x "$DIS" ] || { echo "test.sh: $BX / $DIS missing — run mayhem/build.sh" >&2; exit 1; }
W=$(mktemp -d "${TMPDIR:-/tmp}/bochs-test.XXXXXX")
trap 'rm -rf "$W"' EXIT
pass=0; fail=0
ok()  { echo "PASS: $1"; pass=$((pass+1)); }
bad() { echo "FAIL: $1"; fail=$((fail+1)); }

# 10 MB flat image (20/16/63) with markers in the first, a middle and the last sector
head -c 10321920 /dev/zero > "$W/src.img"
printf 'bochs-mbr-marker' | dd of="$W/src.img" conv=notrunc bs=1 seek=0 status=none
printf 'middle sector data' | dd of="$W/src.img" conv=notrunc bs=1 seek=$((512*10000)) status=none
printf 'last sector!' | dd of="$W/src.img" conv=notrunc bs=1 seek=$((10321920-512)) status=none

for m in sparse growing vpc vhdx vmware4; do
  rm -f "$W/$m.img" "$W/$m.back"
  if "$BX" -q -func=convert -imgmode=$m "$W/src.img" "$W/$m.img" >/dev/null 2>&1 \
     && "$BX" -q -func=info "$W/$m.img" 2>&1 | grep -q "disk image mode = '$m'" \
     && "$BX" -q -func=info "$W/$m.img" 2>&1 | grep -q "geometry = 20/16/63" \
     && "$BX" -q -func=convert -imgmode=flat "$W/$m.img" "$W/$m.back" >/dev/null 2>&1 \
     && cmp -s "$W/src.img" "$W/$m.back"; then
    ok "roundtrip flat->$m->flat"
  else
    bad "roundtrip flat->$m->flat"
  fi
done

dis_case() {  # mode hex expected-substring...
  local mode=$1 hex=$2; shift 2
  local out; out=$("$DIS" "$mode" "$hex" 2>&1)
  for e in "$@"; do
    grep -qF -- "$e" <<<"$out" || { bad "bxdisasm $mode $hex ($e)"; return; }
  done
  ok "bxdisasm $mode $hex"
}
dis_case -64 0f05c3 "disasm: syscall" "disasm: ret " "BX_IA_RET_Op64"
dis_case -32 5589e5 "disasm: push ebp" "disasm: mov ebp, esp"
dis_case -16 b80000cd10 "disasm: mov ax, 0x0000" "disasm: int 0x10"
dis_case -64 4889e5 "disasm: mov rbp, rsp" "disasm: movq %rsp, %rbp"

emit_ctrf "bochs-bximage-bxdisasm" "$pass" "$fail" 0
