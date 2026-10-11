#!/usr/bin/env bash
# Runs on VM-local fs (/tmp/fuzzwork) to avoid 9p slowness. Parallel + dict.
set -u
DUR="${1:-480}"
W=/tmp/fuzzwork
cd "$W"
export AFL_SKIP_CPUFREQ=1 AFL_AUTORESUME=1 AFL_IMPORT_FIRST=1 AFL_NO_UI=0
ln -sf /dev/null /tmp/sentinel_telemetry.log   # stop the shared log from growing

run() {
  local t="$1"
  local out="out/$t"
  rm -rf "$out"; mkdir -p "$out"
  echo "######## $t : ${DUR}s x4 cores + dict ########"
  timeout $((DUR+40)) afl-fuzz -i "seeds/seeds_$t" -o "$out" -x "dics/$t.dict" -t 30000 \
     -V "$DUR" -M f00 -- "./bin/sentinel_$t" @@ >"$out/f00.log" 2>&1 &
  for i in 1 2 3; do
    timeout $((DUR+40)) afl-fuzz -i "seeds/seeds_$t" -o "$out" -x "dics/$t.dict" -t 30000 \
       -V "$DUR" -S "f0$i" -- "./bin/sentinel_$t" @@ >"$out/f0$i.log" 2>&1 &
  done
  wait
}
# dict dir name fix
ln -sfn dicts dics 2>/dev/null
run telemetry
run payload
run network
echo "######## LOCAL CAMPAIGN DONE ########"
