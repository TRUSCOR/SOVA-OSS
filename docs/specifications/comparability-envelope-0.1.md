<!-- status: implemented -->

# Comparability envelope and calibration report 0.1

## Role

A fresh run of a recorded finding answers two questions: how often the attack
works now, and whether the recorded outcome was reproduced. The second answer is
meaningful only when the fresh run's setup is comparable with the recorded one.
The *comparability envelope* declares which setup differences block that
comparison (material) and which are only recorded. The *calibration report*
measures, on one model, which differences actually change how often findings
recur, and derives an envelope from that measurement.

`sova rerun` and `sova matrix` read an envelope with `--envelope FILE`.
`sova calibrate` writes `calibration.json` and `envelope.json`. Neither file
grants authority to run anything.

## Context dimensions

A run's context is a mapping from these dimension names to values, taken from
the run's trace (`run.started`, `prompt.system`, and provider-returned model
events) or, when the trace does not record them, from the scenario parameters:

| Dimension | Value |
|---|---|
| `model` | requested model id |
| `benchmarkVersion` | benchmark suite version |
| `attack` | attack name |
| `defense` | defense name, or `null` for none |
| `toolOutputFormat` | normalized tool-output format (`yaml` when unset) |
| `systemPrompt` | `sha256:` digest of the system prompt text |
| `attackName` | how the attack text addresses the model |
| `returnedModel` | sorted list of the model strings the provider reported |

A value that neither the trace nor the parameters record is absent. An absent
value is never guessed.

## Envelope file

```json
{"dimensions": {"<dimension>": "<mode>" | {"mode": "<mode>", "allowed": [...], "tolerance": n, "required": bool}}}
```

Top-level keys other than `dimensions` are ignored by readers; `sova calibrate`
uses a `measured` key to record the model and measured classes. A dimension
outside the table above is rejected. Dimensions not listed keep their default
rule.

| Mode | Fresh value compared with recorded value |
|---|---|
| `exact` | equal: compatible; different: incompatible |
| `one-of` | fresh value in `allowed`: compatible; otherwise incompatible |
| `tolerance` | numeric absolute difference at most `tolerance`: compatible; larger: incompatible; non-numeric or no tolerance: unknown |
| `record` | equal: compatible; different: drifted (does not block) |
| `ignore` | always compatible |

`required` defaults to true for `exact`, `one-of` and `tolerance`, and false for
`record` and `ignore`. When either value is absent, a required dimension is
unknown and an unrequired one is drifted.

The default envelope is: `model`, `defense`, `benchmarkVersion` and `attack`
exact; `toolOutputFormat`, `systemPrompt` and `returnedModel` recorded and not
required.

The aggregate context is `incompatible` if any dimension is, otherwise `unknown`
if any is, otherwise `drifted` if any is, otherwise `compatible`. An
incompatible fresh run cannot reproduce or fail to reproduce the recorded
outcome; its outcome still counts toward the rate on the new setup.

## Measured classes

Given findings, one model, and a set of changes, each finding is run unchanged
and under each change. For a finding and a condition, recurrence is attacks
divided by judged runs; runs that could not be judged are left out, and a
finding with no judged run on a side is left out of that side. For each change:

1. the unchanged rate and the changed rate are each the mean over findings;
2. the drop is the unchanged rate minus the changed rate;
3. the 95% interval is the 2.5th and 97.5th percentile, by linear interpolation
   between ranks, of the drop over bootstrap resamples that draw findings with
   replacement (default 2,000 resamples, seed 20261113);
4. the change is `material` if the interval's lower end is at least the
   threshold (default 0.10), `non-material` if its upper end is below the
   threshold, and `undetermined` otherwise or when no interval exists.

## Envelope derived from a calibration

| Change | Dimension | Non-material | Material or undetermined |
|---|---|---|---|
| `json` | `toolOutputFormat` | `record` | `exact` |
| `paraphrase` | `systemPrompt` | `record` | `exact` |
| `model` (needs an alternative model) | `model` | `one-of` [model, alternative] | `exact` |
| `repeat-user-prompt`, `spotlighting` | `defense` | `one-of` [baseline defense, each non-material defense] | `exact` when no defense change is non-material |

An undetermined change is treated as material, so the derived envelope never
admits a comparison that the measurement did not support.

## Calibration report

`calibration.json` is canonical SOVA JSON (decimal strings, no binary floats):

| Field | Meaning |
|---|---|
| `artifactType`, `schemaVersion` | `sova.calibration`, `0.1.0` |
| `model`, `alternative`, `provider`, `settings` | what ran; settings never contain keys |
| `trialsPerCell`, `threshold`, `bootstrap` | the measurement's parameters |
| `findings[]` | per finding: capsule name and digest, episode, and the outcome per condition (`unchanged` and each change) |
| `changes[]` | per change: dimension, findings with runs on both sides, unchanged and changed recurrence, drop, `drop95`, and `measured` |
| `envelope` | the derived envelope file |
| `runs`, `spend` | fresh, reused, not-started and budget-stopped runs; estimated cost |
| `limitations` | what the measurement does not establish |

## Limits

A measured class holds for that model, those findings and those settings. It
says nothing about other models, other attacks or later model versions, and it
should be measured again after any of them changes. The bootstrap treats
findings as exchangeable; findings drawn from a narrow set of tasks give
intervals that are narrower than the population's.
