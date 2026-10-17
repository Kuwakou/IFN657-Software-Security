# Comprehensive Seeding Documentation & Presentation Dossier
**Component:** `sentinel_payload.c` (Scientific Observation & Imaging Frame Parser)  
**Assessment Area:** Task 1: Setup & Seed Generation (IFN657 Assignment 2)  
**Author:** Sentinel-1 Flight Software Security Team  

---

## Executive Summary: Seeding Strategy

In coverage-guided fuzzing with AFL++, the quality, diversity, and structural validity of initial seed inputs directly dictate campaign efficacy. If initial seeds are malformed, the parser rejects them at shallow validation stages, preventing the fuzzer from exploring deep parsing paths. Conversely, if seeds trigger crashes immediately, the fuzzer cannot establish a baseline state.

For `sentinel_payload.c`, our team constructed a corpus of **5 diverse, non-crashing seeds** (the maximum range specified in the assignment criteria), exercising:
1. Baseline 2D observation matrices
2. 1D linear observation vectors
3. 3D volumetric multi-spectral cubes
4. Upper-bound memory capacity boundary conditions
5. Minimal non-trivial single-byte observations

---

## 1. Target Format Specification & Parsing Grammar

The target parser `sentinel_payload.c` enforces a multi-phase structural format:

```text
+-------------------------------------------------------------------------+
| HEADER LINE (ASCII, newline-terminated '\n')                            |
| "PAYLOAD_FRAME <width> <height> <depth> <label>\n"                      |
+-------------------------------------------------------------------------+
| BINARY PAYLOAD STREAM (Raw bytes)                                       |
| Total Length = (width * height * depth) bytes                           |
+-------------------------------------------------------------------------+
```

### Structural Validity Rules Enforced by Our Seed Generator:
1. **Header Token Alignment**: Exactly four tokens parsed via `sscanf(header_line, "PAYLOAD_FRAME %u %u %u %127s", ...)`.
2. **Label Length Constraint**: The buffer `local_label` in `process_frame_label()` has a maximum capacity of 64 bytes (`MAX_LABEL_LEN = 64`). All valid seeds constrain the label string length to $\le 21$ characters, ensuring baseline executions never trigger stack canary or overflow aborts.
3. **Dimension Arithmetic**: Total required bytes are calculated as:
   $$\text{expected\_data\_size} = \text{width} \times \text{height} \times \text{depth}$$
4. **Buffer Capacity Containment**: The internal storage descriptor (`global_frame->size`) is fixed at 1024 bytes (`MAX_FRAME_CAPACITY = 1024`). All valid seeds enforce $\text{expected\_data\_size} \le 1024$ bytes to prevent heap corruption during baseline ingestion.
5. **Exact Stream Synchronization**: The binary stream appended after the newline character exactly matches $\text{expected\_data\_size}$ bytes, satisfying `fread()` without underflow or truncation.

---

## 2. Seed Corpus Comparison Matrix

| # | Seed Filename | Category | Dimensions ($W \times H \times D$) | Header Size | Payload Size | Total File Size | Label String | Execution Branch Exercised |
|:---:|:---|:---|:---:|:---:|:---:|:---:|:---|:---|
| **1** | `seed_payload.bin` | Starter Baseline | $8 \times 8 \times 1$ | 34 B | 64 B | 98 B | `RADAR_SCAN_01` | Standard 2D planar sensor stream |
| **2** | `seed_payload_vector.bin` | 1D Linear Vector | $16 \times 1 \times 1$ | 38 B | 16 B | 54 B | `SPECTRAL_BAND_05` | Linear 1D vector processing branch |
| **3** | `seed_payload_matrix.bin` | 3D Volumetric | $16 \times 16 \times 2$ | 43 B | 512 B | 555 B | `DEEP_SPACE_MATRIX_V2` | High-depth 3D observation matrix |
| **4** | `seed_payload_boundary.bin` | Boundary Upper Bound | $32 \times 32 \times 1$ | 39 B | 1024 B | 1063 B | `MAX_CAP_BOUND_01` | Stress-tests exact `MAX_FRAME_CAPACITY` boundary |
| **5** | `seed_payload_minimal.bin` | Minimal Frame | $1 \times 1 \times 1$ | 33 B | 1 B | 34 B | `MIN_FRAME_01` | Minimal non-trivial single-byte observation |

---

## 3. Annotated Binary Inspection & Hex Dumps

### Seed 1: `seed_payload.bin` (98 Bytes)
```text
00000000: 5041 594c 4f41 445f 4652 414d 4520 3820  PAYLOAD_FRAME 8 
00000010: 3820 3120 5241 4441 525f 5343 414e 5f30  8 1 RADAR_SCAN_0
00000020: 310a 4141 4141 4141 4141 4141 4141 4141  1.AAAAAAAAAAAAAA  <-- 0x0A is newline, followed by 64 bytes 'A' (0x41)
00000030: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000040: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000050: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000060: 4141                                      AA
```

### Seed 4: `seed_payload_boundary.bin` (1063 Bytes — Boundary Test)
```text
00000000: 5041 594c 4f41 445f 4652 414d 4520 3332  PAYLOAD_FRAME 32
00000010: 2033 3220 3120 4d41 585f 4341 505f 424f   32 1 MAX_CAP_BO
00000020: 554e 445f 3031 0a5a 5b58 595e 5f5c 5d52  UND_01.Z[XY^_\]R  <-- 1024 unique structured bytes
...
```

---

## 4. Automated Verification & Clean Execution Evidence

All seeds were validated against `sentinel_payload` compiled with debugging symbols and AddressSanitizer.

### Automated Test Runner Execution Output:
```text
==========================================================================
        SENTINEL-1 SCIENTIFIC PAYLOAD: SEED GENERATION & VALIDATION       
==========================================================================
Filename                     | Type / Paradigm                | Size      
--------------------------------------------------------------------------
seed_payload.bin             | Starter Baseline (2D Radar)    | 98 bytes
seed_payload_vector.bin      | 1D Linear Spectral Vector      | 54 bytes
seed_payload_matrix.bin      | 3D Multi-Spectral Observation  | 555 bytes
seed_payload_boundary.bin    | Maximum Boundary Buffer (1024) | 1063 bytes
seed_payload_minimal.bin     | Minimal Single-Byte Frame      | 34 bytes
--------------------------------------------------------------------------

[+] Validating all seeds against target binary (sentinel_payload_gcc)...
--------------------------------------------------------------------------
Seed Input                   | Dimensions               | Exit Code  | Status
--------------------------------------------------------------------------
seed_payload.bin             | 8 x 8 x 1 (64 bytes)     | 0          | PASS (Valid)
seed_payload_vector.bin      | 16 x 1 x 1 (16 bytes)    | 0          | PASS (Valid)
seed_payload_matrix.bin      | 16 x 16 x 2 (512 bytes)  | 0          | PASS (Valid)
seed_payload_boundary.bin    | 32 x 32 x 1 (1024 bytes) | 0          | PASS (Valid)
seed_payload_minimal.bin     | 1 x 1 x 1 (1 byte)       | 0          | PASS (Valid)
--------------------------------------------------------------------------
[SUCCESS] All 5 seeds are structurally valid and cleanly processed with 0 crashes!
```

---

## 5. Presentation Script for Tutorial & Team Meetings

When presenting this work during the Week 13 tutorial or your group sync:

> *"For `sentinel_payload.c`, our primary objective in Task 1 was to build a seed corpus that maximizes code coverage without triggering premature crashes.*  
>  
> *Rather than supplying arbitrary random strings, we systematically modeled the parser's state machine. We generated 5 diverse seeds spanning 1D linear vectors, 2D radar scans, 3D observation cubes, and a boundary stress-test targeting the exact 1024-byte buffer ceiling.*  
>  
> *Each seed is guaranteed to satisfy header grammar, stay strictly within label length limits, and synchronize byte counts with fread expectations. As demonstrated by our automated test suite, all 5 seeds execute with return code 0, providing AFL++ with optimal baseline test cases to discover deep memory corruption vulnerabilities."*
