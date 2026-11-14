<!-- status: implemented -->

# What is stable in SOVA OSS 0.1

SOVA OSS 0.1.0 is the first release published to PyPI (`pip install sova-oss`). Under
[ADR-0002](../decisions/0002-versioning-and-lossless-migration.md) every `0.y.z` release is
experimental, so this page states exactly which parts we commit to not breaking, and which can
still change.

## Frozen: the file formats

| Format | Specification | Version | Commitment |
|---|---|---|---|
| `.sova` capsule | [sova-capsule-0.1](../specifications/sova-capsule-0.1.md) | schema `0.1.0` | frozen |
| `.sova-trace` | [sova-trace-0.1](../specifications/sova-trace-0.1.md) | schema `0.1.0` | frozen |
| Comparability envelope and calibration report | [comparability-envelope-0.1](../specifications/comparability-envelope-0.1.md) | `sova.calibration` `0.1.0` | frozen |

Frozen means:

- A file written at one of these versions is never reinterpreted. Its schema, canonical form and
  digest rules do not change.
- Every later SOVA release can open, verify and show it, offline, and migrates it losslessly when
  a newer format version exists. A field it cannot carry forward is reported, never dropped.
- A change to a format is a new format version, with a migrator, a changelog entry, and a
  conformance vector. It is never an edit to `0.1.0`.

Other tools may read and write these formats from the specifications alone. The conformance kit
(`sova conformance verify`) checks an implementation against the published vectors.

## Stable within 0.1.x: the core commands

These command-line leaves keep their names, options, exit codes, and the keys of their JSON output
across every `0.1.x` release. A `0.1.x` release may add options, output keys, and new change
types or modes, but does not remove or rename any.

| Command | What it does |
|---|---|
| `sova record agentdojo` | AgentDojo run log to `.sova-trace` and `.sova` |
| `sova record inspect-log` | Inspect AI eval log to `.sova-trace` per sample and `.sova` per log |
| `sova verify` | Offline integrity check of a capsule or trace |
| `sova show` | Capsule summary or trace timeline; runs nothing |
| `sova compare` | Declared outcomes of two traces, without re-running |
| `sova audit` | Benchmark attack verdicts checked against each episode's tool calls |
| `sova rerun` | A recorded finding run again, with a Wilson interval and a comparability verdict |
| `sova matrix` | Findings across models, with `--fail-on` for CI |
| `sova calibrate` | Measured per-model envelope for `sova rerun --envelope` |

The test suite fails if any of these leaves is removed or renamed (`STABLE_CLI_LEAVES` in
`src/sova/front_door.py`).

## Experimental: everything else

- The Python API. Import paths, function signatures and classes under `sova.*` may change in any
  `0.y` release. Use the command line or the file formats for anything you depend on.
- Every other command group, including `target`, `methodology`, `adapter`, `detonate`, `hunt`,
  `forensics`, `compose`, `rehearse`, `trace`, `replay`, `evidence`, `case`, `arena`, `engine`,
  `agent`, `registry`, `monitor`, `probe`, `mcp`, `acceptance`, `conformance` and `release`, and
  the `record inspect` and `record trace` importers.
- Every other artifact family and schema in `src/sova/schemas/`, unless listed above.
- The production-worker isolation contracts. They are implemented locally but not validated on a
  dedicated host, and nothing in 0.1 claims hostile-agent isolation.

## Deprecation

Within `0.1.x`, nothing in the stable lists above is removed. A stable command or option that is to
be replaced in `0.2` is first marked deprecated in a `0.1.x` release, with the replacement named in
its help text and in the changelog, and keeps working until `0.2.0`. Frozen formats follow the
deprecation policy of ADR-0002: a deprecated format version is still read, verified and migrated;
it is only no longer written.

## Reporting a break

A change that breaks anything listed as frozen or stable is a bug. Report it at
<https://github.com/TRUSCOR/SOVA-OSS/issues> with the SOVA version and the file or command line.
