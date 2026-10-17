# Original Project — Sentinel-1 Onboard Subsystem Source Files

## Overview
This directory contains the **original, unmodified C source files** and **baseline seed inputs** provided for the IFN657 Assignment 2 security assessment.

### Target Modules
| Module | File | Description |
|:---|:---|:---|
| Payload Parser | `sentinel_payload.c` | Scientific Observation & Imaging Frame Parser (primary assessment target) |
| Telemetry Daemon | `sentinel_telemetry.c` | Telemetry & Housekeeping configuration parser |
| Network Daemon | `sentinel_network.c` | Ground Station Communication packet processor |

### Baseline Seeds
Located in `seeds/`:
- `seed_payload.bin` — Baseline 8×8×1 imaging frame for `sentinel_payload.c`
- `seed_network.bin` — Baseline command packet for `sentinel_network.c`
- `seed_telemetry.conf` — Baseline config input for `sentinel_telemetry.c`

### Compilation
```bash
gcc -g -O0 sentinel_payload.c -o sentinel_payload
gcc -g -O0 sentinel_telemetry.c -o sentinel_telemetry
gcc -g -O0 sentinel_network.c -o sentinel_network
```
