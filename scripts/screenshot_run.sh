#!/usr/bin/env bash
#
# Task 2 helper: launch ONE live afl-fuzz status console for screenshotting.
# Runs on the VM's local disk so exec/s looks healthy, single instance so the
# full-screen status TUI is clean. Let it run ~30-60s, screenshot, then Ctrl-C.
#
# Usage (inside the Lima VM):  scripts/screenshot_run.sh telemetry
#                              scripts/screenshot_run.sh payload
#                              scripts/screenshot_run.sh network
set -u
T="${1:?usage: screenshot_run.sh <telemetry|payload|network>}"
REPO="/Users/dezii/Documents/GitHub/IFN657-Software-Security"
W=/tmp/fuzzwork

# Prep local working copy (binaries + seeds + dicts) if not already there.
mkdir -p "$W/bin" "$W/seeds" "$W/dicts"
cp "$REPO/build/afl/sentinel_$T" "$W/bin/" 2>/dev/null || {
    echo "[*] building AFL binary for $T ..."
    ( cd "$REPO" && afl-cc -g -O1 -fno-omit-frame-pointer "targets/sentinel_$T.c" -o "$W/bin/sentinel_$T" )
}
cp -r "$REPO/targets/seeds_$T" "$W/seeds/seeds_$T" 2>/dev/null || true
cp "$REPO/scripts/dicts/$T.dict" "$W/dicts/" 2>/dev/null || true
ln -sf /dev/null /tmp/sentinel_telemetry.log   # keep telemetry fast

export AFL_SKIP_CPUFREQ=1
echo "[*] Launching live AFL++ for $T. Let it run ~45s, take your screenshot,"
echo "    then press Ctrl-C to stop."
sleep 2
cd "$W"
exec afl-fuzz -i "seeds/seeds_$T" -o "out_shot_$T" -x "dicts/$T.dict" -t 30000 \
     -- "./bin/sentinel_$T" @@
