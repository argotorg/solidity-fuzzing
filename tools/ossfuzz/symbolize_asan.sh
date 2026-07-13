#!/usr/bin/env bash
# Symbolize an AddressSanitizer report captured by run_ossfuzz_afl_asan.sh.
#
# afl-fuzz forces ASAN_OPTIONS=symbolize=0, so the reports written to
# <findings>/asan.<pid> carry raw "(/path/to/module+0xoffset)" frames instead of
# function/file:line. This rewrites each such frame in place using
# llvm-symbolizer against the (debug-info-bearing) module.
#
#   tools/ossfuzz/symbolize_asan.sh <findings>/asan.<pid>
#   tools/ossfuzz/symbolize_asan.sh <findings>/asan.*      # all of them
#
# Reads from stdin if no file is given. Needs llvm-symbolizer (llvm package).
set -eu

SYMB="${LLVM_SYMBOLIZER:-llvm-symbolizer}"
command -v "$SYMB" >/dev/null || { echo "need llvm-symbolizer (set LLVM_SYMBOLIZER=...)" >&2; exit 1; }

symbolize_stream() {
  # Match "(<module>+0x<hex>)" and replace with the resolved "func file:line".
  # Everything else passes through untouched.
  sed -E 's/.*\(([^()]+)\+0x([0-9a-fA-F]+)\).*/\1 0x\2/;t;d' /dev/null >/dev/null 2>&1 || true
  while IFS= read -r line; do
    # Extract module path and offset from a frame like:
    #   #3 0x55...  (/path/lib.so+0x12345)
    if [[ "$line" =~ \(([^()]+)\+0x([0-9a-fA-F]+)\) ]]; then
      mod="${BASH_REMATCH[1]}"; off="0x${BASH_REMATCH[2]}"
      if [ -f "$mod" ]; then
        loc="$("$SYMB" --obj="$mod" --functions=short --inlines "$off" 2>/dev/null \
                 | paste -sd' ' - | sed 's/  */ /g')"
        [ -n "$loc" ] && { printf '%s   [%s]\n' "$line" "$loc"; continue; }
      fi
    fi
    printf '%s\n' "$line"
  done
}

if [ "$#" -eq 0 ]; then
  symbolize_stream
else
  for f in "$@"; do
    echo "===== $f ====="
    symbolize_stream < "$f"
  done
fi
