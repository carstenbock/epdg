#!/bin/bash
# Compile all Diameter .dia dictionary sources to .erl / .hrl using
# diameter_make from the OTP standard library. Invoked by rebar3
# pre_compile hook (see rebar.config).
set -euo pipefail

DIA_DIR="apps/epdg/priv/dict"
OUT_DIR="apps/epdg/src"
INC_DIR="apps/epdg/include"

mkdir -p "$INC_DIR"

if [ ! -d "$DIA_DIR" ]; then
  echo "[diameter] no dict source directory $DIA_DIR, skipping"
  exit 0
fi

shopt -s nullglob
DIA_FILES=("$DIA_DIR"/*.dia)
if [ "${#DIA_FILES[@]}" -eq 0 ]; then
  echo "[diameter] no .dia files in $DIA_DIR, skipping"
  exit 0
fi

for f in "${DIA_FILES[@]}"; do
  base=$(basename "$f" .dia)
  gen_src="$OUT_DIR/diameter_gen_${base}.erl"
  gen_hdr="$INC_DIR/diameter_gen_${base}.hrl"

  # Rebuild only if the .dia is newer than the generated .erl
  if [ -f "$gen_src" ] && [ "$f" -ot "$gen_src" ]; then
    continue
  fi

  echo "[diameter] compiling $f"
  erl -noshell -eval "
    case diameter_make:codec(\"$f\", [erl, hrl, {outdir, \"$OUT_DIR\"}, {include, \"$INC_DIR\"}]) of
      ok -> halt(0);
      {error, R} -> io:format(\"ERROR: ~p~n\", [R]), halt(1);
      R -> io:format(\"UNEXPECTED: ~p~n\", [R]), halt(1)
    end." || { echo "[diameter] FAILED compiling $f"; exit 1; }

  # diameter_make writes .hrl next to the .erl; relocate if needed.
  if [ -f "$OUT_DIR/diameter_gen_${base}.hrl" ]; then
    mv -f "$OUT_DIR/diameter_gen_${base}.hrl" "$INC_DIR/"
  fi
done

echo "[diameter] dictionaries up-to-date"
