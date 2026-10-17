# Task 1: Seed Corpus Generation & Validation

## Objective
Construct a diverse corpus of **5 structurally valid, non-crashing seed inputs** for `sentinel_payload.c` to maximize AFL++ code coverage during fuzzing.

## Seed Corpus Summary

| # | File | Category | Dimensions | Payload Size |
|:---:|:---|:---|:---:|:---:|
| 1 | `seed_payload.bin` | Baseline 2D Radar Scan | 8×8×1 | 64 B |
| 2 | `seed_payload_vector.bin` | 1D Linear Spectral Vector | 16×1×1 | 16 B |
| 3 | `seed_payload_matrix.bin` | 3D Multi-Spectral Matrix | 16×16×2 | 512 B |
| 4 | `seed_payload_boundary.bin` | MAX_FRAME_CAPACITY Boundary | 32×32×1 | 1024 B |
| 5 | `seed_payload_minimal.bin` | Minimal Single-Byte Frame | 1×1×1 | 1 B |

## Usage

### Generate Seeds
```bash
cd Task_1_Seeding/seeds
python3 generate_seeds.py
```

### Validate Seeds Against Target
```bash
python3 Task_1_Seeding/seed_validation/validate_seeds.py
```

All 5 seeds execute with exit code 0 (zero crashes).

## Documentation
Detailed seeding strategy, hex dumps, and presentation notes: `evidence/TASK1_SEEDING_REPORT.md`
