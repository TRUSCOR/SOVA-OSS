<!-- status: implemented -->

# Release compatibility matrix

| Surface | Current contract | Validation | Stability |
|---|---|---|---|
| Python/CLI | `0.1.0`, CPython 3.11-3.14 | Windows/macOS/Linux CI | core commands stable within 0.1.x; Python API experimental ([api-stability](api-stability.md)) |
| `.sova` | schema `0.1.0` | parser, canonicalization, migration, hostile ZIP tests | frozen ([api-stability](api-stability.md)) |
| `.sova-trace` | schema `0.1.0` | streaming, recovery, redaction, integrity, hostile input | frozen ([api-stability](api-stability.md)) |
| MCP | protocol `2025-11-25`, SOVA manifest `0.1.0` | manifest digest and conformance tests | experimental |
| OpenTelemetry | semantic conventions `1.43.0` mapping | loss-reporting compatibility tests | pinned mapping |
| Conformance kit | `0.1.0` | byte reproducibility and hostile ZIP verification | experimental |

Atlas/MELRA availability never changes artifact interpretation. Provider and
external-adapter support is capability-negotiated and may degrade visibly.
Container behavior is documented but is not a supported platform until CI runs
an actual container job.
