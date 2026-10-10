# IFN657 Assignment 2: Vulnerability Discovery

**Group ID:** `Group_12`  
**Submission Date:** `16 Oct 2026`  

### Team Members & Workload Distribution
| Student Name | Student ID | Email Address | Assigned Subtasks / Roles | Contribution (%) |
| :--- | :--- | :--- | :--- | :--- |
| `Koutaro Kuwahara` | `n12282901` | `koutaro.kuwahara@connect.qut.edu.au` | `Task 1 and 4` | 25% |
| `[Full Name 2]` | `[n0000002]` | `[student2@connect.qut.edu.au]` | `[e.g. Payload parser, GDB/sanitisers crash triage]` | 25% |
| `[Full Name 3]` | `[n0000003]` | `[student3@connect.qut.edu.au]` | `[e.g. Network handler, AFL++ parallel fuzzing]` | 25% |
| `[Full Name 4]` | `[n0000004]` | `[student4@connect.qut.edu.au]` | `[e.g. Code remediation, Regression testing, Demo]` | 25% |

**Submission Files (Canvas):**
- `Group_12.pdf` (compiled from this completed Markdown report template)
- `Group_12.zip` (archive containing `seeds/`, `crashes/`, `exploits/`, `remediated_src/`, `README.md`, and `Group_XX.cast`)

<!-- Instructions: Complete this template with your technical analysis, AFL++ metrics, GDB/sanitiser evidence, code fixes, and exploit scripts. Export to Group_XX.pdf before submitting. Ensure that formatting, tables, code blocks, and screenshots render cleanly and legibly. -->

---

## Table of Contents
1. [Task 0: Executive Summary](#1-task-0-executive-summary)
2. [Task 1: Setup](#2-task-1-setup)
3. [Task 2: Fuzzing Execution](#3-task-2-fuzzing-execution)
4. [Task 3: Vulnerability Analysis](#4-task-3-vulnerability-analysis)
5. [Task 4: Code Remediation](#5-task-4-code-remediation)
6. [Task 5: Proof-of-Concept Exploitation](#6-task-5-proof-of-concept-exploitation)

---

## 1. Task 0: Executive Summary

*[State which tasks have been completed and provide the exact timestamp (minutes:seconds) where each practical task is demonstrated in your `Group_XX.cast` recording file. Note: Marks for vulnerability analysis and code remediation are directly capped by the number of valid, distinct vulnerabilities discovered.]*

| Task | Status | `asciinema` Timestamp (mm:ss) | Notes |
| :--- | :--- | :--- | :--- |
| **Task 0: Claims, Demo & Teamwork** | [Completed / Incomplete] | [00:00] | Any additional notes. |
| **Task 1: Setup** | [Completed / Incomplete]  | [00:30] | Briefly describe how this task is completed. |
| **Task 2: Fuzzing Execution** | [Completed / Incomplete]  | [01:30] | Briefly describe how this task is completed. |
| **Task 3: Vulnerability Analysis** | [Completed / Incomplete]  | [03:00] | Briefly describe how this task is completed. |
| **Task 4: Code Remediation** | [Completed / Incomplete]  | [05:30] | Briefly describe how this task is completed. |
| **Task 5: Proof-of-Concept Exploitation** | [Completed / Incomplete]  | [07:00] | Briefly describe how this task is completed. |
| **Total Number of Distinct Vulnerabilities Found** | [The total number] | N/A | Any additional notes. |

---

## 2. Task 1: Setup

### 2.1 Compilation & Target Environment Setup

All three were compiled in two configurations. The first uses AFL++LLVM instrumentation (`afl-clang-fast`), which inserts edge-coverage tracking so the fuzzer can measure which braches an input reaches and evolve its corpus toward new coverage. The second adds `AddressSanitizer (ASAN)` and `UndefineBehaiviorSanitizer (UBSAN)`, which abort the instant a memory-safety or undefined-behaviour violation occurs rather than only on a hard crash into an immediate, diagnoable report for triage in Task 3. The original target source was not modified during compilation. 

`afl-clang-fast` was chosen over the tutorial `afl-gcc -m32` because the build environment is ARM, and -m32 targets 32-bits x86 and is unsupported on this architecture, and `afl-gcc` is not available on the ARM Ubuntu Server. `afl-clang-fast` is AFL++'s recommended LLVM-mode compiler, provides equivalent edge-coverage instrumentation, links the sanitisers cleanly, and supports persistent-mode fuzzing (used in Task 2)


```bash
# Compilation commands with AFL++ instrumentation (ARM version)
afl-clang-fast -std=gnu99 -w -o sentinel_telemetry_fuzz targets/sentinel_telemetry.c 
afl-clang-fast -std=gnu99 -w -o sentinel_payload_fuzz targets/sentinel_payload.c 
afl-clang-fast -std=gnu99 -w -o sentinel_network_fuzz targets/sentinel_network.c 
```

```bash
# Compilation commands with AddressSanitizer and UndefinedBehaviorSanitizer
export AFL_USE_ASAN=1      # AddressSanitizer – memory corruption (overflows, UAF)
export AFL_USE_UBSAN=1     # UndefinedBehaviorSanitizer – integer overflow / UB
afl-clang-fast -std=gnu99 -w -g -o sentinel_telemetry_asan targets/sentinel_telemetry.c
afl-clang-fast -std=gnu99 -w -g -o sentinel_payload_asan   targets/sentinel_payload.c
afl-clang-fast -std=gnu99 -w -g -o sentinel_network_asan   targets/sentinel_network.c
unset AFL_USE_ASAN AFL_USE_UBSAN
```

`-std=gnu=99` sets the language standard to C99 with GNU extentions, which is required because the targets call functions such as `strdup()` that are POSIX/GNU additions and not part of strict IOS C99, `-w` suppresses the warning in the vulnerable sources, `-g` embeds debug symbols so GDB and the sanitisers report function names and line numbers during triage. No `-m32` is used, as the target architecture is 64-bit ARM. 

## Environment ##
- Component: `Ubuntu 26.04`
- Architecture: `aarch64 (ARM)`
- AFL++: `afl-fuzz++4.33c`
- Compiler: `afl-cc++4.33c`
- Core-dump handler: `echo core | sudo tee /proc/sys/kernel/core_pattern`


### 2.2 Seed Corpus
*[Detail the 3 to 5 valid seeds created for each target program. Explain why each seed is structurally valid and what parsing path it exercises.]*

#### Target 1: `sentinel_telemetry` Seed Set
| Seed Filename | Input Content / Syntax Summary | Target Branch / Parsing State Exercised |
| :--- | :--- | :--- |
| `seed_telemetry.conf` | Starter configuration with nominal directives | Base parser validation and comment handling |
| `seed_telemetry_a.conf` | Two `sensor_id_*`, two `cal_factor_*`, `log_event`, `stream_multiplier=2` | `process_sensor_calibration` - `sscanf %d` (sensor id) and `sscanf %f` (cal factor) paths, `log_event` logging, `stream_multiplier` buffer free+realloc |
| `seed_telemetry_b.conf` | `aux_buffer_request=256`, `sensor_id_array`, `cal_factor_radar`, `log_event`, `stream_multiplier=8` | `aux_buffer_request` -> `allocate_auxiliary_buffer` (`malloc`) branch, not reached by the others |
| `seed_telemetry_c.conf` | Safe-hold profile, same recognised keys, `stream_multiplier=1` | `Re-covers directive handlers with different values/state (minimum multiplier)` |

#### Target 2: `sentinel_payload` Seed Set
| Seed Filename | Dimensions & Label | Payload Size | Target Branch / Parsing State Exercised |
| :--- | :--- | :--- | :--- |
| `seed_payload.bin` | `PAYLOAD_FRAME 8 8 1 RADAR_SCAN_01` | 64 bytes | Standard 2D observation matrix |
| `seed_payload_a.bin` | `PAYLOAD_FRAME 4 4 1 IMG_CAL_04` | `16 bytes` | `Small single-plan frame, smaller malloc(w*h*d+1) sizing, shorter label. ` |
| `seed_payload_b.bin` | `PAYLOAD_FRAME 8 8 3 MULTISPEC_SCAN_07` | `192 bytes` | `depth>1 multi-spectral path, width*height*depth sizing` |
| `seed_payload_c.bin` | `PAYLOAD_FRAME 16 16 1 RADAR_WIDEBAND_SURVEY_PASS` | `256 bytes` | `Larger frame + loger label (<64B), larger buffer, still under 1024B` |

#### Target 3: `sentinel_network` Seed Set
| Seed Filename | Magic Header & Type | Payload Length | Target Branch / Parsing State Exercised |
| :--- | :--- | :--- | :--- |
| `seed_network.bin` | `0x12345678`, Type 1 | 16 bytes | Station status message queue handling |
| `seed_network_a.bin` | `0x12345678`, Type 1 | `18 bytes` | `Type-1 path with NUL-terminated payload so log_telecommand_header's %s reads safely` |
| `seed_network_b.bin` | `0x12345678`, Type 3` | `19 bytes` | `Type-3 emergency-failover switch arm -> emergency_command_cleanup (empty queue, safe)` |
| `seed_network_c.bin` | `0x12345678`, Type-1 * 2 | `2 packets (9 + 9)` | `multi-packet dispatch loop - offset advance and a second packets is parsed` |

### 2.3 Seed Generation Methodology & Helper Scripts
```python
"""
IFN657-Software-Security/generate_seeds.py
Task 1: seed generator
"""
import struct, os
 
BASE = os.path.dirname(os.path.abspath(__file__))
# Each seed goes into its matching target folder under targets/.
FOLDERS = {
    "telemetry": os.path.join(BASE, "targets", "seeds_telemetry"),
    "payload":   os.path.join(BASE, "targets", "seeds_payload"),
    "network":   os.path.join(BASE, "targets", "seeds_network"),
}
for folder in FOLDERS.values():
    os.makedirs(folder, exist_ok=True)
 
def write(name, data: bytes):
    # choose the folder by which target word appears in the file name
    folder = next(f for key, f in FOLDERS.items() if key in name)
    path = os.path.join(folder, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"  {path:55s} {len(data):4d} bytes")

# target 1: sentinel_telemetry
print ("[telemetry]")
# Seed A: tests sensor, calibration, logging, and stream paths. 
telem_a = (
    b"# seed A - calibration & stream profile\n"
    # generic key-value entry
    b"subsystem_mode=standby\n"
    # test the sensor_id * parser path with two different sensor ID
    b"sensor_id_primary=204\n"
    b"sensor_id_secondary=205\n"
    # test the cal_factor_ * parser path with two calibration values
    b"cal_factor_thermal=0.98\n"
    b"cal_factor_optical=1.12\n"
    # test the logging path
    b"log_event=calibration_sweep_start\n"
    # test the stream multiplir path
    b"stream_multiplier=2\n"
)
write("seed_telemetry_a.conf", telem_a)
# Seed B and C use the same pattern but different value (due to the page limitation)
# target 2: sentinel_payload
print("[payload]")

def payload_frame(w, h, d, label: bytes, fill):
    # calculate the required number of data byte
    n = w * h * d

    # build frame header 
    header = b"PAYLOAD_FRAME %d %d %d %s\n" % (w, h, d, label)
    # generate the binary data
    body = bytes(fill(i) for i in range(n)) if callable(fill) else bytes([fill]) * n
    # return complete frame
    return header + body

# Seed A: small single-plane frame.
write(
    "seed_payload_a.bin",
    payload_frame(
        4,  #width
        4,  #height
        1,  #depth
        b"IMG_CAL_04", #frame label
        lambda i: i & 0xFF #sequential byte pattern
    )
)
# Seed B and C use the same pattern but different value (due to the page limitation)
# target 3: sentinel_network (binary packet)
print("[network]")
# magic value expected by the network parser
MAGIC = 0x12345678

def packet(ptype, payload: bytes):
    # Build the packet header and append the payload.
    return struct.pack("<IHH", MAGIC, ptype, len(payload)) + payload

# Seed A: Type 1 packet containing a normal station status message.
# The trailing NUL safely terminates the payload as a C string.
write(
    "seed_network_a.bin",
    packet(1, b"STATION_STATUS_OK\x00")
)
# Seed B and C use the same pattern but different value (due to the page limitation)
# All six seeds have now been generated.
print("\nDone. 6 seeds in ./seeds/")
```

---

## 3. Task 2: Fuzzing Execution

### 3.1 Fuzzing Execution & Advanced Techniques
*[Describe the AFL++ execution parameters, directory structures, and advanced techniques employed (e.g. parallel fuzzing, dictionary files, persistent mode). Justify your choices.]*

```bash
# Example AFL++ execution commands used by your team

```

**Technical Justification:**
`[Explain why these options and techniques were chosen and how they improved coverage/efficiency]`

### 3.2 Campaign Performance & Coverage Metrics
*[Summarise the fuzzing campaign results across all three targets.]*

| Target Program | Campaign Duration | Total Executions | Execution Speed (exec/s) | Total Paths Discovered | Unique Crashes Reported |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `sentinel_telemetry` | `[e.g. 6.5 hours]` | `[e.g. 12.4M]` | `[e.g. 1,250/sec]` | `[e.g. 48 paths]` | `[e.g. 14 crashes]` | 
| `sentinel_payload` | `[Hours]` | `[Executions]` | `[Exec/sec]` | `[Paths]` | `[Crashes]` | 
| `sentinel_network` | `[Hours]` | `[Executions]` | `[Exec/sec]` | `[Paths]` | `[Crashes]` |

### 3.3 AFL++ Status Console Screenshots
*[Embed clear screenshots of the AFL++ status consoles for each target program demonstrating your fuzzing campaigns.]*

```
[Insert Screenshot: sentinel_telemetry AFL++ Status Screen]
```

```
[Insert Screenshot: sentinel_payload AFL++ Status Screen]
```

```
[Insert Screenshot: sentinel_network AFL++ Status Screen]
```

---

## 4. Task 3: Vulnerability Analysis

### 4.1 Crash Triage Methodology
*[Explain how your team deduplicated and triaged crashes using GDB and AddressSanitizer logs to isolate distinct root causes from duplicate crashing inputs.]*

`[Complete this section]`

### 4.2 Discovered Vulnerabilities
*[Report distinct vulnerabilities across the target suite. Complete each vulnerability sub-section below.]*

---

#### 4.2.1 Vulnerability 1
| Field | Details |
| :--- | :--- |
| **Vulnerability Name** | `[e.g. Format String Vulnerability in Telemetry Logger]` |
| **CWE Classification** | `[e.g. CWE-134: Use of Externally-Controlled Format String]` |
| **Target Component** | `[e.g. sentinel_telemetry.c]` |
| **Vulnerable Location** | `[Function name, line number, and code snippet]` |
| **Reproducing Input File** | `[e.g. crashes/id_000000_telemetry_crash.conf]` |

**Triggering Input & Reproduction Command:**
```bash
# Provide command to reproduce the crash

```

**Root Cause Analysis:**
`[Explain the technical root cause, memory state, and why the input leads to corruption]`

**GDB / Sanitiser Evidence:**
```text
[Paste annotated Sanitiser error report or GDB backtrace here]
```

**Exploitability Assessment:**
`[Assess the severity and realistic attacker impact (e.g. memory leak, DoS, arbitrary write)]`

---

#### 4.2.2 Vulnerability 2
| Field | Details |
| :--- | :--- |
| **Vulnerability Name** | `[e.g. Integer Overflow in Stream Buffer Calculation]` |
| **CWE Classification** | `[e.g. CWE-190: Integer Overflow or Wraparound]` |
| **Target Component** | `[e.g. sentinel_telemetry.c]` |
| **Vulnerable Location** | `[Function name, line number, and code snippet]` |
| **Reproducing Input File** | `[e.g. crashes/id_000001_stream_overflow.conf]` |

**Triggering Input & Reproduction Command:**
```bash
# Provide command to reproduce the crash

```

**Root Cause Analysis:**
`[Explain the technical root cause, memory state, and why the input leads to corruption]`

**GDB / Sanitiser Evidence:**
```text
[Paste annotated Sanitiser error report or GDB backtrace here]
```

**Exploitability Assessment:**
`[Assess the severity and realistic attacker impact]`

---

#### 4.2.3 Vulnerability X (numbered sequentially for each distinct vulnerability)
| Field | Details |
| :--- | :--- |
| **Vulnerability Name** | `[e.g. Stack Buffer Overflow in Frame Label Processing]` |
| **CWE Classification** | `[e.g. CWE-121: Stack-based Buffer Overflow]` |
| **Target Component** | `[e.g. sentinel_payload.c]` |
| **Vulnerable Location** | `[Function name, line number, and code snippet]` |
| **Reproducing Input File** | `[e.g. crashes/id_000002_payload_label_overflow.bin]` |

**Triggering Input & Reproduction Command:**
```bash
# Provide command to reproduce the crash

```

**Root Cause Analysis:**
`[Explain the technical root cause, memory state, and why the input leads to corruption]`

**GDB / Sanitiser Evidence:**
```text
[Paste annotated Sanitiser error report or GDB backtrace here]
```

**Exploitability Assessment:**
`[Assess the severity and realistic attacker impact]`

---

## 5. Task 4: Code Remediation

### 5.1 Proposed Code-Level Remediations
*[Provide sound, robust C code fixes for every identified vulnerability. Explain how each fix prevents memory corruption without breaking legitimate parsing functionality.]*

#### Patch for Vulnerability 1 (`sentinel_telemetry.c`):
```c
// Provide the corrected C code block or diff
```
**Technical Justification:**
`[Explain how the patch fixes the root cause]`

#### Patch for Vulnerability 2 (`sentinel_telemetry.c`):
```c
// Provide the corrected C code block or diff
```
**Technical Justification:**
`[Explain how the patch fixes the root cause]`

#### Patch for Vulnerability X (`sentinel_payload.c`):
```c
// Provide the corrected C code block or diff
```
**Technical Justification:**
`[Explain how the patch fixes the root cause]`

### 5.2 Regression Verification & Fuzzing Proof
*[Demonstrate that your patched target binaries run cleanly on previously crashing inputs and continue to accept valid seed inputs without errors.]*

```bash
# Demonstrate executing the patched binaries against all triggering crash inputs

```

**Regression Fuzzing Observations:**
`[Document your regression campaign results proving zero new crashes occurred during re-fuzzing]`

---

## 6. Task 5: Proof-of-Concept Exploitation

### 6.1 Target Vulnerability & Security Consequence
*[Specify which critical vulnerability was chosen for exploitation. Describe the intended actionable security consequence beyond a simple crash (e.g. arbitrary memory write, stack leak, control flow hijacking, or state flag overwrite).]*

- **Target Component:** `[e.g. sentinel_telemetry.c / sentinel_payload.c / sentinel_network.c]`
- **Vulnerability Selected:** `[e.g. Format String Arbitrary Write / Stack Buffer Overflow Hijack]`
- **Actionable Exploit Consequence:** `[Describe the tangible exploit objective achieved]`

### 6.2 Memory Layout & Address Analysis
*[Detail the memory state, stack/heap frame layout, resolved target addresses, GDB memory dumps, and endianness considerations.]*

`[Complete this section with stack/memory diagrams and GDB address resolution steps]`

### 6.3 Complete Exploit Script
*[Provide your full, working Python exploit script or shell payload generator.]*

```python
#!/usr/bin/env python3
"""
IFN657 Assignment 2: Proof-of-Concept Exploit Script
Target: [Target component name]
Security Consequence: [Actionable consequence description]
"""

# Insert complete Python exploit script here
```

### 6.4 Reproduction Instructions & Live Bash Evidence
*[Provide step-by-step commands to compile and execute your exploit in standard bash, accompanied by terminal output proving successful exploitation.]*

```bash
# Commands to execute the exploit
# For example, `python3 exploit.py > exploit_payload.bin` then `./target_binary exploit_payload.bin`
```

**Observed Terminal Output & Verification:**
```text
[Paste terminal output proving successful exploit execution]
```

