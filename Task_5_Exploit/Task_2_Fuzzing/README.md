# Task 2: AFL++ Fuzzing Campaign

## Objective
Execute a coverage-guided fuzzing campaign using AFL++ to discover crashes and vulnerabilities in `sentinel_payload.c`.

## Campaign Configuration
- **Fuzzer:** AFL++ v4.33c (LLVM mode via `afl-clang-fast`)
- **Dictionary:** `fuzz_results/payload.dict` (domain-specific tokens)
- **Seed Corpus:** Validated Task 1 seeds

### Execution Command
```bash
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
afl-fuzz -i fuzz_in -o fuzz_out -x payload.dict -V 30 -- ./sentinel_payload_afl @@
```

## Results Summary

| Metric | Value |
|:---|:---|
| Total Executions | 1,277+ |
| Exec/sec | ~42.5 |
| Stability | 100.00% |
| Bitmap Coverage | 26.19% |
| Unique Crashes | 1 |

## Crash Discovery
- **File:** `crashes/crash_afl_format_string.bin`
- **Signal:** SIGSEGV (Signal 11)
- **Root Cause:** Format string specifiers injected into `log_payload_error()` via havoc mutation

## Documentation
Full campaign analysis: `evidence/AFL_CAMPAIGN_REPORT.md`
