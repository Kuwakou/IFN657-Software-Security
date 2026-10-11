#!/usr/bin/env bash
#
# IFN657 A2 - Task 2 fuzzing campaign (improved: parallel + dictionary).
# Builds on Kou's Task 1 seeds (targets/seeds_<target>/).
#
# Each target runs a synchronised multi-core campaign:
#   1 primary (-M) + 3 secondaries (-S) sharing one output dir, each pinned to
#   a core, seeded with a per-target dictionary. AFL runs for $DUR seconds
#   (-V) then exits, so the whole thing is reproducible and unattended.
#
# Usage: scripts/task2_fuzz.sh [seconds_per_target]   (default 600)
set -u
cd "$(dirname "$0")/.."
DUR="${1:-600}"
export AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=0 AFL_AUTORESUME=1 AFL_IMPORT_FIRST=1

run_target() {
  local t="$1" seeds="$2" dict="$3"
  local out="task2_out/${t}"
  rm -rf "$out"; mkdir -p "$out"
  echo "######## FUZZING $t  (${DUR}s, 4 cores, dict=$(basename "$dict")) ########"
  # primary
  timeout $((DUR+30)) afl-fuzz -i "$seeds" -o "$out" -x "$dict" -t 30000 \
      -V "$DUR" -M f00 -- "build/afl/sentinel_${t}" @@ >"$out/f00.log" 2>&1 &
  # secondaries
  for i in 1 2 3; do
    timeout $((DUR+30)) afl-fuzz -i "$seeds" -o "$out" -x "$dict" -t 30000 \
        -V "$DUR" -S "f0${i}" -- "build/afl/sentinel_${t}" @@ >"$out/f0${i}.log" 2>&1 &
  done
  wait
  echo "---- aggregated stats for $t ----"
  python3 - "$out" <<'PY'
import sys, glob, os
out = sys.argv[1]
tot_execs = 0; tot_crashes = 0; speed = 0.0; paths = 0; cvg = 0.0; rt = 0
for fs in glob.glob(os.path.join(out, "*", "fuzzer_stats")):
    d = {}
    for line in open(fs):
        if ":" in line:
            k, v = line.split(":", 1); d[k.strip()] = v.strip()
    tot_execs += int(d.get("execs_done", 0))
    tot_crashes += int(d.get("saved_crashes", 0))
    speed += float(d.get("execs_per_sec", 0))
    paths = max(paths, int(d.get("corpus_count", 0)))
    cvg = max(cvg, float(d.get("bitmap_cvg", "0").rstrip("%")))
    rt = max(rt, int(d.get("run_time", 0)))
# dedup crashes across the synced dir (unique crash files)
uniq = len(glob.glob(os.path.join(out, "*", "crashes", "id:*")))
print(f"  run_time(s)     : {rt}")
print(f"  total_execs     : {tot_execs:,}")
print(f"  aggregate_speed : {speed:,.0f} exec/s (sum of 4 cores)")
print(f"  paths(corpus)   : {paths}")
print(f"  coverage        : {cvg:.2f}%")
print(f"  crashes(summed) : {tot_crashes}   unique_files: {uniq}")
PY
}

run_target telemetry targets/seeds_telemetry scripts/dicts/telemetry.dict
run_target payload   targets/seeds_payload   scripts/dicts/payload.dict
run_target network   targets/seeds_network   scripts/dicts/network.dict

echo "######## ALL CAMPAIGNS DONE ########"
