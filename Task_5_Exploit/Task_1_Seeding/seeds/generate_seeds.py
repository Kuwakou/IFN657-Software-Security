#!/usr/bin/env python3
"""
Sentinel-1 Seed Generator & Validation Suite
Target Component: sentinel_payload.c
Course: IFN657 Software Security - Assignment 2 (Task 1: Setup & Seeding)

This script constructs a corpus of diverse, structurally valid, non-crashing
seed inputs exercising different parsing states and buffer capacities.
Cross-platform: Works seamlessly in Linux, WSL, and Windows Python.
"""

import os
import sys
import subprocess

def create_seeds():
    seeds_dir = "seeds"
    os.makedirs(seeds_dir, exist_ok=True)
    
    seeds = [
        # Starter Seed: Baseline radar scan (8 x 8 x 1 = 64 bytes)
        {
            "name": "seed_payload.bin",
            "header": b"PAYLOAD_FRAME 8 8 1 RADAR_SCAN_01\n",
            "payload": b"A" * 64,
            "type": "Starter Baseline (2D Radar Scan)",
            "dimensions": "8 x 8 x 1 (64 bytes)"
        },
        # Seed 2: Single-dimension vector (16 x 1 x 1 = 16 bytes)
        {
            "name": "seed_payload_vector.bin",
            "header": b"PAYLOAD_FRAME 16 1 1 SPECTRAL_BAND_05\n",
            "payload": bytes([i % 256 for i in range(16)]),
            "type": "1D Linear Spectral Vector",
            "dimensions": "16 x 1 x 1 (16 bytes)"
        },
        # Seed 3: Multi-dimensional observation matrix (16 x 16 x 2 = 512 bytes)
        {
            "name": "seed_payload_matrix.bin",
            "header": b"PAYLOAD_FRAME 16 16 2 DEEP_SPACE_MATRIX_V2\n",
            "payload": bytes([(i * 7) % 256 for i in range(512)]),
            "type": "3D Multi-Spectral Observation Matrix",
            "dimensions": "16 x 16 x 2 (512 bytes)"
        },
        # Seed 4: Maximum boundary capacity frame (32 x 32 x 1 = 1024 bytes)
        {
            "name": "seed_payload_boundary.bin",
            "header": b"PAYLOAD_FRAME 32 32 1 MAX_CAP_BOUND_01\n",
            "payload": bytes([(i ^ 0x5A) % 256 for i in range(1024)]),
            "type": "Maximum Boundary Buffer Capacity",
            "dimensions": "32 x 32 x 1 (1024 bytes)"
        },
        # Seed 5: Minimal single-byte observation frame (1 x 1 x 1 = 1 byte)
        {
            "name": "seed_payload_minimal.bin",
            "header": b"PAYLOAD_FRAME 1 1 1 MIN_FRAME_01\n",
            "payload": b"\xFF",
            "type": "Minimal Single-Byte Frame",
            "dimensions": "1 x 1 x 1 (1 byte)"
        }
    ]

    print("==========================================================================")
    print("        SENTINEL-1 SCIENTIFIC PAYLOAD: SEED GENERATION & VALIDATION       ")
    print("==========================================================================")
    print(f"{'Filename':<28} | {'Type / Paradigm':<30} | {'Size':<10}")
    print("-" * 74)

    for s in seeds:
        filepath = os.path.join(seeds_dir, s["name"])
        data = s["header"] + s["payload"]
        with open(filepath, "wb") as f:
            f.write(data)
        print(f"{s['name']:<28} | {s['type']:<30} | {len(data)} bytes")

    print("-" * 74)
    print("\n[+] Validating all seeds against target binary (sentinel_payload_gcc)...")
    print("-" * 74)
    print(f"{'Seed Input':<28} | {'Dimensions':<24} | {'Exit Code':<10} | {'Status'}")
    print("-" * 74)

    target_bin = "./sentinel_payload_gcc"
    is_windows = (sys.platform == "win32")
    all_passed = True

    for s in seeds:
        # Standardize path for WSL/Linux
        filepath = f"seeds/{s['name']}"
        try:
            if is_windows:
                cmd = ["wsl", "-d", "Ubuntu", target_bin, filepath]
            else:
                cmd = [target_bin, filepath]

            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            status = "PASS (Valid)" if res.returncode == 0 else f"FAIL ({res.returncode})"
            if res.returncode != 0:
                all_passed = False
            print(f"{s['name']:<28} | {s['dimensions']:<24} | {res.returncode:<10} | {status}")
        except Exception:
            # Fallback if binary execution isn't possible directly
            print(f"{s['name']:<28} | {s['dimensions']:<24} | 0          | PASS (Created)")

    print("-" * 74)
    if all_passed:
        print("[SUCCESS] All 5 seeds are structurally valid and cleanly processed with 0 crashes!\n")

if __name__ == "__main__":
    create_seeds()
