# Concepts

Second-brain semantic layer: nouns map atomically to file sets (EXTRACTED); verbs aggregate structural edges (INFERRED).

| Concept | Files | Mentions | Top Files |
|---------|-------|----------|-----------|
| `aes` | 3 | 32 | `aes.c`, `aes.h`, `beacon.c` |
| `get` | 3 | 16 | `aes.c`, `beacon.c`, `cJSON.c` |
| `defined` | 3 | 12 | `aes.c`, `aes.h`, `cJSON.c` |
| `value` | 3 | 11 | `aes.c`, `cJSON.c`, `cJSON.h` |
| `number` | 3 | 10 | `aes.c`, `cJSON.c`, `cJSON.h` |
| `build` | 3 | 6 | `andoid_build.sh`, `armbian_build.sh`, `cJSON.c` |
| `each` | 3 | 5 | `aes.c`, `cJSON.c`, `cJSON.h` |
| `set` | 3 | 5 | `aes.c`, `aes.h`, `cJSON.h` |
| `encrypt` | 3 | 4 | `aes.c`, `aes.h`, `beacon.c` |
| `next` | 3 | 4 | `aes.c`, `cJSON.c`, `cJSON.h` |
| `cjson` | 2 | 95 | `cJSON.c`, `cJSON.h` |
| `buffer` | 2 | 86 | `aes.c`, `cJSON.c` |
| `json` | 2 | 83 | `cJSON.c`, `cJSON.h` |
| `public` | 2 | 75 | `cJSON.c`, `cJSON.h` |
| `const` | 2 | 36 | `cJSON.c`, `cJSON.h` |
| `object` | 2 | 32 | `cJSON.c`, `cJSON.h` |
| `offset` | 2 | 31 | `aes.c`, `cJSON.c` |
| `string` | 2 | 27 | `cJSON.c`, `cJSON.h` |
| `array` | 2 | 23 | `cJSON.c`, `cJSON.h` |
| `hooks` | 2 | 21 | `cJSON.c`, `cJSON.h` |
| `null` | 2 | 20 | `cJSON.c`, `cJSON.h` |
| `size` | 2 | 18 | `aes.h`, `cJSON.c` |
| `bool` | 2 | 15 | `cJSON.c`, `cJSON.h` |
| `define` | 2 | 15 | `cJSON.c`, `cJSON.h` |
| `version` | 2 | 14 | `cJSON.c`, `cJSON.h` |
| `function` | 2 | 13 | `aes.c`, `cJSON.c` |
| `cbc` | 2 | 11 | `aes.c`, `aes.h` |
| `false` | 2 | 11 | `cJSON.c`, `cJSON.h` |
| `true` | 2 | 11 | `cJSON.c`, `cJSON.h` |
| `ctx` | 2 | 9 | `aes.c`, `aes.h` |
| `text` | 2 | 9 | `aes.c`, `cJSON.c` |
| `ctr` | 2 | 8 | `aes.c`, `aes.h` |
| `ecb` | 2 | 8 | `aes.c`, `aes.h` |
| `key` | 2 | 8 | `aes.c`, `aes.h` |
| `add` | 2 | 6 | `aes.c`, `cJSON.c` |
| `bytes` | 2 | 5 | `aes.c`, `cJSON.c` |
| `cdecl` | 2 | 5 | `cJSON.c`, `cJSON.h` |
| `blocklen` | 2 | 4 | `aes.c`, `aes.h` |
| `decrypt` | 2 | 4 | `aes.c`, `beacon.c` |
| `endif` | 2 | 4 | `aes.c`, `cJSON.c` |
| `https` | 2 | 4 | `aes.c`, `beacon.c` |
| `keylen` | 2 | 4 | `aes.c`, `aes.h` |
| `minor` | 2 | 4 | `cJSON.c`, `cJSON.h` |
| `used` | 2 | 4 | `aes.c`, `cJSON.c` |
| `aes256` | 2 | 3 | `aes.h`, `beacon.c` |
| `com` | 2 | 3 | `aes.c`, `app.py` |
| `gcc` | 2 | 3 | `armbian_build.sh`, `cJSON.c` |
| `major` | 2 | 3 | `cJSON.c`, `cJSON.h` |
| `patch` | 2 | 3 | `cJSON.c`, `cJSON.h` |
| `reference` | 2 | 3 | `cJSON.c`, `cJSON.h` |

## Verb Edges

| Source | Verb | Target | Strength |
|--------|------|--------|----------|
| `get` | `consumes` | `set` | 1.00 |
| `get` | `depends_on` | `set` | 1.00 |
| `aes` | `consumes` | `set` | 0.75 |
| `aes` | `depends_on` | `set` | 0.75 |
| `decrypt` | `consumes` | `set` | 0.75 |
| `decrypt` | `depends_on` | `set` | 0.75 |
| `encrypt` | `consumes` | `set` | 0.75 |
| `encrypt` | `depends_on` | `set` | 0.75 |
| `https` | `consumes` | `set` | 0.75 |
| `https` | `depends_on` | `set` | 0.75 |
| `add` | `consumes` | `set` | 0.50 |
| `add` | `depends_on` | `set` | 0.50 |
| `aes` | `consumes` | `aes256` | 0.50 |
| `aes` | `depends_on` | `aes256` | 0.50 |
| `aes` | `consumes` | `blocklen` | 0.50 |
| `aes` | `depends_on` | `blocklen` | 0.50 |
| `aes` | `consumes` | `cbc` | 0.50 |
| `aes` | `depends_on` | `cbc` | 0.50 |
| `aes` | `consumes` | `ctr` | 0.50 |
| `aes` | `depends_on` | `ctr` | 0.50 |
| `aes` | `consumes` | `ctx` | 0.50 |
| `aes` | `depends_on` | `ctx` | 0.50 |
| `aes` | `consumes` | `defined` | 0.50 |
| `aes` | `depends_on` | `defined` | 0.50 |
| `aes` | `consumes` | `ecb` | 0.50 |
| `aes` | `depends_on` | `ecb` | 0.50 |
| `aes` | `consumes` | `encrypt` | 0.50 |
| `aes` | `depends_on` | `encrypt` | 0.50 |
| `aes` | `consumes` | `key` | 0.50 |
| `aes` | `depends_on` | `key` | 0.50 |
| `aes` | `consumes` | `keylen` | 0.50 |
| `aes` | `depends_on` | `keylen` | 0.50 |
| `aes` | `consumes` | `size` | 0.50 |
| `aes` | `depends_on` | `size` | 0.50 |
| `aes256` | `consumes` | `set` | 0.50 |
| `aes256` | `depends_on` | `set` | 0.50 |
| `buffer` | `consumes` | `set` | 0.50 |
| `buffer` | `depends_on` | `set` | 0.50 |
| `bytes` | `consumes` | `set` | 0.50 |
| `bytes` | `depends_on` | `set` | 0.50 |
| `decrypt` | `consumes` | `aes` | 0.50 |
| `decrypt` | `depends_on` | `aes` | 0.50 |
| `decrypt` | `consumes` | `aes256` | 0.50 |
| `decrypt` | `depends_on` | `aes256` | 0.50 |
| `decrypt` | `consumes` | `blocklen` | 0.50 |
| `decrypt` | `depends_on` | `blocklen` | 0.50 |
| `decrypt` | `consumes` | `cbc` | 0.50 |
| `decrypt` | `depends_on` | `cbc` | 0.50 |
| `decrypt` | `consumes` | `ctr` | 0.50 |
| `decrypt` | `depends_on` | `ctr` | 0.50 |

## Dialectic Prompts

- Thesis: `add` centralizes 2 files; Antithesis: `buffer` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `add` centralizes 2 files; Antithesis: `bytes` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `add` centralizes 2 files; Antithesis: `defined` pulls 3 files with 2 shared (Jaccard 0.67); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `add` centralizes 2 files; Antithesis: `each` pulls 3 files with 2 shared (Jaccard 0.67); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `add` centralizes 2 files; Antithesis: `endif` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `add` centralizes 2 files; Antithesis: `function` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `add` centralizes 2 files; Antithesis: `get` pulls 3 files with 2 shared (Jaccard 0.67); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `add` centralizes 2 files; Antithesis: `next` pulls 3 files with 2 shared (Jaccard 0.67); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `add` centralizes 2 files; Antithesis: `number` pulls 3 files with 2 shared (Jaccard 0.67); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `add` centralizes 2 files; Antithesis: `offset` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
