# Gotchas

## God Nodes (high connectivity)

These files have the most connections. Changes here have high blast radius.

- `cJSON.c` (score: 14.50)
- `cJSON.h` (score: 7.70, imported by 2 files)
- `aes.c` (score: 6.30)
- `aes.h` (score: 5.70, imported by 2 files)
- `beacon.c` (score: 5.50)
- `andoid_build.sh` (score: 0.00)
- `app.py` (score: 0.00)
- `armbian_build.sh` (score: 0.00)
- `install.sh` (score: 0.00)

## Blast Radius (change impact)

Editing these files can break the listed number of dependents. Run their tests after any change.

- `aes.h` -- 2 direct, 2 total dependents
- `cJSON.h` -- 2 direct, 2 total dependents

## Hotspots (complexity + centrality)

- `beacon.c` -- complexity: 0.1, centrality: 1.0, combined: 0.6
- `cJSON.c` -- complexity: 1.0, centrality: 0.4, combined: 0.6
- `cJSON.h` -- complexity: 0.3, centrality: 0.2, combined: 0.2
- `aes.c` -- complexity: 0.3, centrality: 0.1, combined: 0.2
- `aes.h` -- complexity: 0.1, centrality: 0.2, combined: 0.2
- `andoid_build.sh` -- complexity: 0.0, centrality: 0.0, combined: 0.0
- `app.py` -- complexity: 0.0, centrality: 0.0, combined: 0.0
- `armbian_build.sh` -- complexity: 0.0, centrality: 0.0, combined: 0.0
- `install.sh` -- complexity: 0.0, centrality: 0.0, combined: 0.0

## Dataflow Issues (INFERRED, review each lead)

- `beacon.c:122` `aes256_cfb_encrypt` [UNCHECKED_ALLOC] `ciphertext`: Result of allocator stored in `ciphertext` is never checked against NULL.
- `beacon.c:150` `aes256_cfb_decrypt` [UNCHECKED_ALLOC] `plaintext`: Result of allocator stored in `plaintext` is never checked against NULL.
- `beacon.c:456` `main` [UNCHECKED_ALLOC] `full_enc`: Result of allocator stored in `full_enc` is never checked against NULL.
- `cJSON.c:1654` `print_array` [DEAD_STORE] `output_pointer`: `output_pointer` assigned at line 1654 but never read afterwards.
- `cJSON.c:1887` `print_object` [DEAD_STORE] `output_pointer`: `output_pointer` assigned at line 1887 but never read afterwards.
