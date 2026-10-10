# IFN657 Assignment 2: Vulnerability Discovery

**Group ID:** `Group_12`  
**Submission Date:** `16 Oct 2026`  

### Team Members & Workload Distribution
| Student Name | Student ID | Email Address | Assigned Subtasks / Roles | Contribution (%) |
| :--- | :--- | :--- | :--- | :--- |
| `Koutaro Kuwahara` | `n12282901` | `koutaro.kuwahara@connect.qut.edu.au` | `[e.g. Lead, Telemetry parser, Exploit development]` | 25% |
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
*[Document your compilation commands for AFL++ instrumentation and sanitisers, as well as system environment configurations if any.]*

```bash
# Compilation commands with AFL++ instrumentation

# Compilation commands with AddressSanitizer and UndefinedBehaviorSanitizer

```

### 2.2 Seed Corpus
*[Detail the 3 to 5 valid seeds created for each target program. Explain why each seed is structurally valid and what parsing path it exercises.]*

#### Target 1: `sentinel_telemetry` Seed Set
| Seed Filename | Input Content / Syntax Summary | Target Branch / Parsing State Exercised |
| :--- | :--- | :--- |
| `seed_telemetry.conf` | Starter configuration with nominal directives | Base parser validation and comment handling |
| `seed_tel_2.conf` | `[Describe content]` | `[Describe branch/rationale]` |
| `seed_tel_3.conf` | `[Describe content]` | `[Describe branch/rationale]` |
| `seed_tel_X.conf` | `[Describe content]` | `[Describe branch/rationale]` |

#### Target 2: `sentinel_payload` Seed Set
| Seed Filename | Dimensions & Label | Payload Size | Target Branch / Parsing State Exercised |
| :--- | :--- | :--- | :--- |
| `seed_payload.bin` | `PAYLOAD_FRAME 8 8 1 RADAR_SCAN_01` | 64 bytes | Standard 2D observation matrix |
| `seed_pay_2.bin` | `[Describe parameters]` | `[Size]` | `[Describe branch/rationale]` |
| `seed_pay_3.bin` | `[Describe parameters]` | `[Size]` | `[Describe branch/rationale]` |
| `seed_pay_X.bin` | `[Describe parameters]` | `[Size]` | `[Describe branch/rationale]` |

#### Target 3: `sentinel_network` Seed Set
| Seed Filename | Magic Header & Type | Payload Length | Target Branch / Parsing State Exercised |
| :--- | :--- | :--- | :--- |
| `seed_network.bin` | `0x12345678`, Type 1 | 16 bytes | Station status message queue handling |
| `seed_net_2.bin` | `[Describe parameters]` | `[Length]` | `[Describe branch/rationale]` |
| `seed_net_3.bin` | `[Describe parameters]` | `[Length]` | `[Describe branch/rationale]` |
| `seed_net_X.bin` | `[Describe parameters]` | `[Length]` | `[Describe branch/rationale]` |

### 2.3 Seed Generation Methodology & Helper Scripts
*[Provide any Python scripts or command-line pipelines used to generate your structured seed corpora.]*

```python
# Insert seed generation Python script here (if applicable)
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

