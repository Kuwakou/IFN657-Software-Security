# Group_12 — IFN657 Assignment 2: Vulnerability Discovery & Exploitation

### 👥 Team Identification
- **Group:** Group_12
- **Member:** Likitha Shivananju (Student ID: N12280453)

## 📖 Overview
This repository contains the complete deliverables for **IFN657 Software Security — Assignment 2** by **Group_12**.

The assignment focuses on the security assessment of the **Sentinel-1 Onboard Subsystem**, specifically the `sentinel_payload.c` (Scientific Payload & Imaging Frame Parser) target binary. The work spans five tasks covering seed generation, fuzzing, vulnerability analysis, code remediation, and proof-of-concept exploitation.

---

## 📂 Repository Structure

```text
Task_5_Exploit/
├── README.md                          # This file — project overview & navigation
│
├── Original_Project/                  # Original vulnerable C source files & baseline seeds
│   ├── sentinel_payload.c             # Primary target: Imaging Frame Parser
│   ├── sentinel_telemetry.c           # Telemetry Daemon (reference)
│   ├── sentinel_network.c             # Network Command Daemon (reference)
│   └── seeds/                         # Baseline seed inputs provided with the project
│
├── Task_1_Seeding/                    # Task 1: Seed Corpus Generation & Validation
│   ├── seeds/                         # 5 diverse, structurally valid seed inputs + generator
│   │   ├── generate_seeds.py          # Automated seed generation script
│   │   ├── seed_payload.bin           # Baseline 8×8×1 radar scan (64B payload)
│   │   ├── seed_payload_vector.bin    # 1D linear spectral vector (16B)
│   │   ├── seed_payload_matrix.bin    # 3D multi-spectral matrix (512B)
│   │   ├── seed_payload_boundary.bin  # Boundary test at MAX_FRAME_CAPACITY (1024B)
│   │   └── seed_payload_minimal.bin   # Minimal single-byte frame (1B)
│   ├── seed_validation/
│   │   └── validate_seeds.py          # Automated seed validation harness
│   └── evidence/
│       └── TASK1_SEEDING_REPORT.md    # Comprehensive seeding strategy documentation
│
├── Task_2_Fuzzing/                    # Task 2: AFL++ Fuzzing Campaign
│   ├── crashes/                       # AFL-discovered crash inputs
│   │   ├── crash_afl_format_string.bin
│   │   └── id000000,sig11,...         # Raw AFL crash artifact
│   ├── fuzz_results/                  # AFL campaign metrics & artifacts
│   │   ├── fuzzer_stats.txt           # Campaign statistics
│   │   ├── plot_data.csv              # Coverage progression data
│   │   ├── payload.dict               # Domain-specific fuzzing dictionary
│   │   ├── cmdline.txt                # Exact AFL command used
│   │   └── queue/                     # AFL queue entries
│   └── evidence/
│       └── AFL_CAMPAIGN_REPORT.md     # Fuzzing campaign analysis dossier
│
├── Task_3_Vulnerability_Analysis/     # Task 3: Crash Triage & Root Cause Analysis
│   ├── evidence/                      # Crash reproduction inputs
│   │   ├── crash_format_string.bin    # CWE-134 Format String trigger
│   │   ├── crash_stack_overflow.bin   # CWE-121 Stack Buffer Overflow trigger
│   │   ├── crash_heap_overflow.bin    # CWE-122 Heap Buffer Overflow trigger
│   │   ├── crash_use_after_free.bin   # CWE-416 Use-After-Free trigger
│   │   └── generate_crash_cases.py    # Crash input generator script
│   └── findings/                      # Individual vulnerability write-ups
│       ├── 01_CWE134_Format_String.md
│       ├── 02_CWE121_Stack_Buffer_Overflow.md
│       ├── 03_CWE122_Heap_Buffer_Overflow.md
│       ├── 04_CWE416_Use_After_Free.md
│       └── 05_CWE190_Integer_Wraparound.md
│
├── Final_Task/                        # Tasks 4 & 5: Remediation & PoC Exploitation
│   ├── source/
│   │   ├── sentinel_payload_vulnerable.c    # Vulnerable source (reference copy)
│   │   ├── sentinel_payload_remediated.c    # Fully patched secure version
│   │   └── patch_diff.patch                 # Unified diff of all security fixes
│   ├── poc/
│   │   ├── exploit_payload.py               # PoC exploit generator script
│   │   ├── exploit_memory_leak.bin          # Format String → ASLR bypass payload
│   │   └── exploit_control_flow.bin         # Stack Overflow → RIP hijack payload
│   ├── tests/
│   │   └── run_tests.py                     # Automated exploit & regression test harness
│   ├── evidence/
│   │   └── EXPLOIT_AND_REMEDIATION_EVIDENCE.md  # GDB, ASan & memory layout proofs
│   ├── logs/
│   │   └── remediation_verification.log     # Terminal output of regression tests
│   └── Makefile                             # Build automation for all binaries
│
└── Asciinema/                         # Terminal Recording Demo
    ├── Group_12.cast                  # Full asciinema recording demonstrating all tasks
    └── demo_session.sh               # Script used to generate the recording
```

---

## 🛠️ Prerequisites

| Component | Purpose | Installation (WSL Ubuntu) |
|-----------|---------|---------------------------|
| **WSL 2** (Ubuntu) | Linux environment for tooling | `wsl --install -d Ubuntu` |
| **gcc / clang** | Compile C source (plain & instrumented) | `sudo apt install build-essential clang` |
| **AFL++** | Coverage-guided fuzzing | `sudo apt install afl++` |
| **gdb** | Crash triage & debugging | `sudo apt install gdb` |
| **python3** | Seed generation & test scripts | `sudo apt install python3` |
| **asciinema** | Terminal recording playback | `sudo apt install asciinema` |

> **Note:** All commands should be run **inside the Ubuntu WSL shell**.

---

## 🚀 Quick Reproduction Guide

### 1. Navigate to the project
```bash
cd '/mnt/c/Users/<your-username>/path/to/Group_12'
```

### 2. Build all target binaries
```bash
cd Final_Task
make all
cd ..
```
This produces 4 binaries in `Final_Task/bin/`:
- `sentinel_payload_gcc` — Standard GCC build
- `sentinel_payload_nopie` — No PIE/canary (for deterministic RIP control)
- `sentinel_payload_asan` — AddressSanitizer build (crash verification)
- `sentinel_payload_remediated_asan` — Patched binary with ASan

### 3. Validate seed corpus (Task 1)
```bash
python3 Task_1_Seeding/seed_validation/validate_seeds.py
```

### 4. Run the complete test suite (Tasks 4 & 5)
```bash
python3 Final_Task/tests/run_tests.py
```

### 5. Replay the Asciinema demo
```bash
asciinema play Asciinema/Group_12.cast
```

---

## 🔍 Vulnerabilities Discovered

| # | CWE | Vulnerability | Severity | Impact |
|:---:|:---:|:---|:---:|:---|
| 1 | CWE-134 | Uncontrolled Format String | Critical | ASLR bypass, arbitrary memory read/write |
| 2 | CWE-121 | Stack Buffer Overflow | Critical | Control flow hijack (RIP overwrite) |
| 3 | CWE-122 | Heap Buffer Overflow | High | Heap metadata corruption |
| 4 | CWE-416 | Use-After-Free | High | Dangling pointer dereference |
| 5 | CWE-190 | Integer Wraparound | Medium | Size calculation bypass |

---

## ✅ Deliverables Checklist

- [x] **Task 1:** 5 diverse, valid seed inputs with generation script & validation harness
- [x] **Task 2:** AFL++ fuzzing campaign with crash discovery, dictionary, and statistics
- [x] **Task 3:** 5 vulnerability findings with CWE classification, root cause analysis, and crash reproduction
- [x] **Task 4:** Fully remediated source code with patch diff and regression testing (100% pass rate)
- [x] **Task 5:** Actionable PoC exploits — ASLR bypass via format string & RIP hijack via stack overflow
- [x] **Asciinema:** Full terminal recording demonstrating all tasks (`Group_12.cast`)

---

## 📎 Key Evidence Files

| Deliverable | File |
|:---|:---|
| Asciinema Recording | `Asciinema/Group_12.cast` |
| Seeding Report | `Task_1_Seeding/evidence/TASK1_SEEDING_REPORT.md` |
| Fuzzing Report | `Task_2_Fuzzing/evidence/AFL_CAMPAIGN_REPORT.md` |
| Vulnerability Findings | `Task_3_Vulnerability_Analysis/findings/` |
| Remediation Evidence | `Final_Task/evidence/EXPLOIT_AND_REMEDIATION_EVIDENCE.md` |
| Regression Test Log | `Final_Task/logs/remediation_verification.log` |
| Security Patch | `Final_Task/source/patch_diff.patch` |
