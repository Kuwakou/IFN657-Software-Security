# Task 2: AFL++ Fuzzing Campaign & Coverage Analysis Dossier
**Component:** `sentinel_payload.c` (Scientific Imaging Frame Parser)  
**Tooling:** AFL++ v4.33c (`afl-clang-fast` instrumented binary `sentinel_payload_afl`)  
**Assessment Area:** Task 2: Fuzzing Execution & Code Coverage (IFN657 Assignment 2)  

---

## 1. Fuzzing Environment & Campaign Architecture

The fuzzing campaign was executed using AFL++ v4.33c with LLVM mode (`afl-clang-fast`) instrumentation:
- **Target Binary:** `sentinel_payload_afl` compiled with `-g -O2`
- **Seed Input Corpus:** `fuzz_in/` (derived from validated Task 1 seeds)
- **Token Dictionary:** `payload.dict` providing domain-specific grammar tokens:
  - Header keywords: `"PAYLOAD_FRAME"`, `"RADAR_SCAN"`, `"SPECTRAL"`
  - Boundary markers: `"\x00"`, `"\n"`, `"1337"` (magic trigger for UAF logic)
  - Format specifiers: `"%s"`, `"%n"`, `"%x"`, `"%p"`

### Execution Command:
```bash
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
afl-fuzz -i fuzz_in -o fuzz_out -x payload.dict -V 30 -- ./sentinel_payload_afl @@
```

---

## 2. Quantitative Campaign Metrics (`fuzzer_stats`)

| Metric Category | Parameter | Recorded Value | Significance |
|---|---|---|---|
| **Speed & Throughput** | Total Executions | 1,277+ | Robust mutation velocity |
| **Speed & Throughput** | Executions per Second | ~42.5 exec/s | Stable execution rate under WSL2 emulation |
| **Execution Stability** | Stability | 100.00% | Zero non-deterministic jitter in target |
| **Code Coverage** | Bitmap Coverage | 26.19% | Explored major parsing and error branches |
| **Path Transitions** | Edges Found | 11 / 42 total edges | Covered critical branching decisions |
| **Crash Discovery** | Unique Saved Crashes | 1 | Discovered `%n` format string write crash |

---

## 3. Crash Capture & Triage
AFL++ successfully synthesized a crash input via havoc mutation:
- **Discovered Crash File:** `Task_2_Fuzzing/crashes/crash_afl_format_string.bin`
- **Mutation Operation:** `op:havoc,rep:15`
- **Triggered Mechanism:** Injected format specifiers into the `label` parameter, which triggered `fprintf(stderr, error_description)` in `log_payload_error()`, resulting in a Segmentation Fault (`SIGSEGV`, Signal 11).

---

## 4. Evidence Artifacts
- **Dictionary File:** `Task_2_Fuzzing/fuzz_results/payload.dict`
- **Fuzzer Stats:** `Task_2_Fuzzing/fuzz_results/fuzzer_stats.txt`
- **Plot Data:** `Task_2_Fuzzing/fuzz_results/plot_data.csv`
- **Command Line:** `Task_2_Fuzzing/fuzz_results/cmdline.txt`
- **Discovered Crash:** `Task_2_Fuzzing/crashes/crash_afl_format_string.bin`
