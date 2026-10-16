# IFN657 Software Security — Assignment 2
 
**Group:** Group_12
**Targets:** Sentinel-1 Space Station firmware — `sentinel_telemetry`, `sentinel_payload`, `sentinel_network`
 
This archive contains the practical artefacts for the AFL++ fuzzing campaign, the
reproducing crash inputs, the exploit material, and the remediated source for the
three target programs. Each item below lists its **purpose**, the **input syntax**
it expects, and **how to execute / reproduce** it.

---
 
## Archive layout
 
```
Group_XX/
├── seeds/              # Fuzzing seed corpora (one subfolder per target)
├── crashes/            # Unique crashing inputs, one per reported bug
├── exploits/           # Exploit script, payloads, and run instructions
├── remediated_src/     # Patched, secured C source for all three targets
├── README.md           # This manifest
└── Group_XX.cast       # asciinema recording of the validation run
```
 
---

## Prerequisites
 
| Tool | Purpose |
|------|---------|
| `gcc` / `clang` | Compile the targets and remediated source |
| AFL++ (`afl-fuzz`, `afl-cc`) | Reproduce the fuzzing campaign |
| `python3` | Run the input generators and exploit script |
| `asciinema` | Play the `.cast` recording |

All three targets take **a single file path as their only argument** and read the
file (telemetry as text, payload and network as binary). None read from stdin.
 
```
./sentinel_telemetry <telemetry_config_file>     # text .conf
./sentinel_payload    <payload_binary_file>       # binary .bin
./sentinel_network    <telecommand_packet_file>   # binary .bin
```
 
---

## `seeds/` — fuzzing seed corpora
 
Valid, well-formed inputs used to seed the AFL++ campaign for each target. These
exercise normal parsing paths and give the fuzzer a starting corpus to mutate.
 
| File | Target | Format | Purpose |
|------|--------|--------|---------|
| `seeds/telemetry/seed_telemetry.conf`, `_a`, `_b`, `_c` | telemetry | text (key=value config) | Baseline telemetry configuration directives |
| `seeds/payload/seed_payload.bin`, `_a`, `_b`, `_c` | payload | binary frame | Valid multi-spectral imaging frame headers + data |
| `seeds/network/seed_network.bin`, `_a`, `_b`, `_c` | network | binary packet | Well-formed telecommand packets (magic `0x12345678`) |
 
**Usage (as AFL++ input dir):**
```bash
afl-fuzz -i seeds/telemetry -o out_telemetry -- ./sentinel_telemetry @@
```
 
---

## `crashes/` — reproducing crash inputs
 
Each file is a **minimised, unique crashing input** that triggers one reported
vulnerability. Reproduce by running the matching target against the file (build
with AddressSanitizer for a clear diagnosis).
 
| File | Target | Reproduces |
|------|--------|-----------|
| `crashes/telemetry_crash_01.conf` | telemetry | Bug #1 (see report) |
| `crashes/telemetry_crash_02.conf` | telemetry | Bug #2 (see report) |
| `crashes/payload_crash_01.bin` | payload | Bug #1 (see report) |
| `crashes/payload_crash_02.bin` | payload | Bug #2 (see report) |
| `crashes/payload_crash_03.bin` | payload | Bug #3 (see report) |
| `crashes/network_crash_01.bin` | network | Bug #1 (see report) |
| `crashes/network_crash_01p5.bin` | network | Bug #1 (variant / refinement) |
 
> Map each crash file to its CWE and root-cause analysis in the written report.
> Keep the labels above consistent with the report's bug numbering.
 
**Reproduce a crash:**
```bash
# Build the target with ASan for a readable crash report
afl-cc -fsanitize=address -g -o sentinel_payload sentinel_payload.c
./sentinel_payload crashes/payload_crash_01.bin
# ASan prints the fault type, address, and backtrace
```
 
---

## `exploits/` — exploit script and payloads
 
Expected contents:
 
| File | Purpose |
|------|---------|
| `exploits/exploit.py` | Python script that builds the malicious input and drives the target to demonstrate control/impact |
| `exploits/payload_*.bin` (or `.conf`) | Generated payload file(s) the script produces or consumes |
| `exploits/INSTRUCTIONS.md` | Step-by-step: how to build the target, run the exploit, and what to observe |
 
**Helper generators included:**
 
| File | Purpose |
|------|---------|
| `exploits/network_seedgen.py` | Generates crafted telecommand packet inputs |
| `exploits/payload_seedgen.py` | Generates crafted payload frame inputs |
 
Run a generator:
```bash
python3 exploits/payload_seedgen.py        # writes its output file(s) to the cwd
```
 
<!-- TODO: once exploit.py exists, document its exact invocation here, e.g.:
python3 exploits/exploit.py && ./sentinel_payload exploits/payload_exploit.bin
and state the expected observable result (e.g. controlled EIP / shell / overwrite). -->
 
---

## `remediated_src/` — patched source
 
Hardened versions of the three targets with the reported vulnerabilities fixed.
Each compiles standalone and should run the matching crash input **without**
crashing (input rejected or handled safely).
 
| File | Target |
|------|--------|
| `remediated_src/sentinel_telemetry.c` | telemetry |
| `remediated_src/sentinel_payload.c` | payload |
| `remediated_src/sentinel_network.c` | network |
 
**Build and verify a fix holds:**
```bash
gcc -fsanitize=address -g -o sentinel_payload_fixed remediated_src/sentinel_payload.c
./sentinel_payload_fixed crashes/payload_crash_01.bin
# Expected: input handled safely / rejected, no ASan crash report
```
 
---

## `Group_12.cast` — validation recording

 
asciinema recording validating the practical work (reproducing a crash, running
the exploit, and showing the remediated build no longer crashing).
 
**Play it:**
```bash
asciinema play Group_12.cast
```
 
**(For reference) record a new one:**
```bash
asciinema rec Group_12.cast
# ... run the demo commands ...
exit   # stops recording
```
 
---

## Reproduction summary (quick path)
 
```bash
# 1. Build a vulnerable target with ASan
afl-cc -fsanitize=address -g -o sentinel_payload sentinel_payload.c
 
# 2. Confirm the crash
./sentinel_payload crashes/payload_crash_01.bin        # ASan reports the fault
 
# 3. Build the remediated target
gcc -fsanitize=address -g -o sentinel_payload_fixed remediated_src/sentinel_payload.c
 
# 4. Confirm the fix
./sentinel_payload_fixed crashes/payload_crash_01.bin  # no crash
 
# 5. (exploit) see exploits/INSTRUCTIONS.md
```
 
Repeat steps 1–4 for `telemetry` and `network` using their respective
`crashes/` files and source.