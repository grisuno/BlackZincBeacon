# Second Brain

*Last synthesized: 2026-10-07 | 9 files | 2 concept pages | offline, zero tokens*

> Raw sources -> readmenator wiki -> links (Karpathy LLM Wiki Pattern, deterministic).
> Start here, then open one community page. Prefer grep over full reads.

## Vault Overview

The codebase centres on `cJSON.c`, `cJSON.h`, `aes.c`. Architecturally it is 1 layers, dominant utility (9 files) across 2 import-based communities. Recorded risk surface: 0 security findings and 0 dependency cycles.

Surprising tissue lives between root, orphans: 0 extracted cross-community imports and 1 inferred bridges. Follow `connections.json` sorted by strength before refactoring.

Open work clusters around documentation (33% file coverage), 0 security findings, 0 taint paths, and 5 suggested exploration questions in `queries.md`.

## Stats

| Metric | Value |
|--------|-------|
| Files | 9 |
| Symbols | 237 |
| Resolved imports | 4 |
| Languages | c, h, py, sh |
| Communities | 2 |
| Doc coverage | 33% (3/9 files) |
| Security findings | 0 |
| Estimated read cost | ~3876 tokens (chars/4, offline so $0) |

## Reading Order

1. Skim Stats and God Nodes below for blast radius.
2. Open the largest community page first, then follow Connections.
3. Use `queries.md` for the next question; log the answer there.

```
grep -rn '<keyword>' index.md community_*.md
readmenator query "<question>" --target readmenator_BlackZincBeacon_0zg6knyl
```

## Concept Wiki

- [root (5 files, cohesion 1.00)](./community_0_root.md)
- [orphans (4 files, cohesion 0.00)](./community_1_orphans.md)

## God Nodes

| File | Score |
|------|-------|
| `cJSON.c` | 14.5 |
| `cJSON.h` | 7.7 |
| `aes.c` | 6.3 |
| `aes.h` | 5.7 |
| `beacon.c` | 5.5 |

## Strongest Connections

- 0 -> 1: shares_context (strength 0.5, INFERRED)

## Navigation Tips

- Obsidian Graph View works: every community page links back here.
- `connections.json` is machine-readable for GraphRAG pipelines.
- `REPORT.md` states what was extracted vs inferred and current limits.
- Regenerate offline: `readmenator . --rebuild` (no network, no tokens).
