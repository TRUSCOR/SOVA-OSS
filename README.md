<p align="center">
  <img src="./assets/sova-owl-logo.svg" width="190" alt="SOVA owl logo" />
</p>

<h1 align="center">S.O.V.A.</h1>

<p align="center">
  <strong>The open-source portable record for AI behavior.</strong>
</p>

<p align="center">
  Record what happened. Package the conditions. Replay the evidence.<br/>
  Reproduce the behavior. Compare systems. Share research others can inspect.
</p>

<p align="center">
  <a href="https://truscor.org"><img alt="TRUSCOR" src="https://img.shields.io/badge/TRUSCOR-Project%20Home-0B8793?style=for-the-badge"></a>
  <a href="https://github.com/TRUSCOR/SOVA-OSS"><img alt="Status" src="https://img.shields.io/badge/STATUS-PRE--ALPHA-FFB000?style=for-the-badge"></a>
  <a href="./LICENSE"><img alt="Apache License 2.0" src="https://img.shields.io/badge/LICENSE-Apache--2.0-D22128?style=for-the-badge"></a>
  <img alt="Local first" src="https://img.shields.io/badge/LOCAL--FIRST-YES-00B8D9?style=for-the-badge">
  <img alt="Telemetry" src="https://img.shields.io/badge/TELEMETRY-OFF%20BY%20DEFAULT-172B4D?style=for-the-badge">
  <img alt="Bring your own model" src="https://img.shields.io/badge/MODEL-BRING%20YOUR%20OWN-6554C0?style=for-the-badge">
</p>

<p align="center">
  <a href="#why-sova">Why SOVA</a> •
  <a href="#what-sova-is-building">Capabilities</a> •
  <a href="#how-the-system-fits-together">System</a> •
  <a href="#the-developer-experience">Usage</a> •
  <a href="#safety-by-construction">Safety</a> •
  <a href="#project-status">Status</a> •
  <a href="#licence-attribution-and-citation">Governance</a> •
  <a href="#connect">Connect</a>
</p>

<br/>

<p align="center">
  <img src="./assets/sova-hero.png" width="100%" alt="SOVA maps an agent system, discovers a dormant trigger, seals the evidence, and produces a forensic replay" />
</p>

---

> [!IMPORTANT]
> **SOVA is pre-alpha.** The repository now implements experimental `0.1`
> `.sova` capsule and `.sova-trace` contracts, deterministic and restricted
> local executors, observable deterministic oracles, capability mapping,
> evidence-isolated orchestration, bounded checking, exact-gated local MCP,
> fail-closed extensions/providers, evidence-first local community surfaces,
> replay, bounded trigger search, evidence-linked causal forensics, onboarding,
> release integrity, neutral conformance vectors, authorized-target planning,
> shared domain primitives, bounded universal-target intake, a deterministic
> methodology compiler, security-tool normalization, an oracle laboratory,
> production-worker control contracts, and blinded-launch evidence gates. The
> worker and launch machinery is implemented locally; live Firecracker isolation,
> blinded multi-provider field results, a public Registry deployment, independent
> review, and publication remain open gates. The built-in loopback fixture now exercises a
> real browser through the pinned Playwright MCP adapter. Operator-owned HTTPS
> targets can use the short-lived well-known control-proof workflow plus exact
> interactive authorization; target-specific procedures, accounts, privacy
> review, and evidence oracles remain the operator's responsibility.

## Implemented foundation, mapping, runtime, capsules, traces, and ecosystem boundaries

The implemented Topic 02–27 engineering foundation is intentionally
experimental and honest:

```bash
git clone https://github.com/TRUSCOR/SOVA-OSS.git
cd SOVA-OSS
uv sync --locked
uv run sova --version
uv run python -m pytest
```

It provides:

- the canonical `sova-oss` Python distribution, `sova` import namespace, and
  `sova` command;
- CPython 3.11–3.14 support across Windows, macOS, and Linux CI;
- pinned JSON Schema 2020-12 validators, an optional Ed25519 signing extra, and
  no SOVA-hosted service requirement;
- locked development dependencies, formatting, linting, strict typing, branch
  coverage, dependency audit, CodeQL, secret scanning, and build checks;
- deterministic seeds, compatibility directories, provenance-controlled
  goldens, performance budgets, fault injection, and crash recovery tests;
- permanent decision, invention, claim, research-artifact, methodology,
  glossary, changelog, security, and release-control homes.
- strict semantic versions, SHA-256 fingerprints, UUIDv7 logical identifiers,
  explicit absence semantics, and stable machine-classifiable contract errors;
- a non-destructive five-axis finding lifecycle and version-qualified external
  vulnerability references;
- the experimental twelve-class `sova.attack` taxonomy with standard/custom
  profile rules and pinned interoperability mappings;
- a six-dimensional observed-coverage vector with frozen denominators,
  exploration budgets, stopping rules, and no universal “percent safe” score.
- deterministic, hostile-input-aware `.sova` packages with content-addressed
  objects, authoring templates, validation, linting, rendering, hashing, and
  chained migrations;
- streaming `.sova-trace` event segments, capture-time redaction, blob
  deduplication, event hash chains, optional DSSE-compatible Ed25519 signatures,
  offline verification, queries, and inert playback;
- pinned OpenTelemetry `1.43.0` and OpenInference `0.1.30` mappings that report
  fidelity loss instead of inventing missing evidence.
- an exact versioned executor capability contract, deterministic
  `ScriptedExecutor`, and an explicitly non-sandboxed `RestrictedLocalExecutor`
  with strict opaque secret references, supervised child processes, visible
  unsupported resource limits, and explicit crash evidence;
- deterministic observable oracles and an integrity-checked declared-outcome
  comparator that returns `inconclusive` when required evidence was lost;
- a safe complete no-Atlas capsule → trace → playback → controlled execution →
  comparison → evidence-capsule → independent-offline-verification fixture.
- air-gapped `sova map` discovery with a typed capability graph, redacted edge
  provenance, declared/witness-linked/possible/conflict closures, and immutable
  tool-definition drift snapshots;
- provider-neutral runtime roles, standard/custom profiles, bounded mutation,
  an evidence firewall that excludes attacker assertions from factual judge
  input, deterministic oracle/policy precedence, and explicit inconclusive and
  human-review states;
- `sova check` and a complete repeated `sova demo sleeper` workflow producing
  signed traces, a portable capsule, a fresh reproduction, and a concise report.
- account-free local initialization, credential-safe diagnostics, reviewed
  managed-data deletion, first-run guides, and air-gapped operation;
- deterministic CycloneDX 1.6 SBOMs, release checksums with undeclared-file
  detection, and reproducible independent conformance kits;
- secret-free authorized target contracts and deterministic website/software
  assessment fixtures that validate the complete evidence pipeline without
  claiming that a live target was exercised.
- a deterministic six-phase methodology compiler backed by 74 versioned native
  web, API, network/cloud, source/package, AI/model, and agentic playbooks, with
  explicit evidence gaps, budgets, non-authorizing effects, and signed local
  Registry contribution review.
- a version-pinned external security-tool catalog with 12 promoted normalizers,
  constrained high-risk/protocol descriptors, an enforced Nmap legal hold,
  authority-routed execution, digest-bound raw observations, and failure states
  that cannot silently become findings.
- an oracle laboratory that separates proposals from promoted deterministic
  checks, requires calibration and independent reproduction, records differential
  and metamorphic evidence, and reports eight measured coverage dimensions without
  converting unobserved or unsupported states into success.
- immutable controller/worker, network-broker, secret-broker, hostile-evidence,
  cleanup, and attestation contracts plus an exact Firecracker launch compiler and
  root-only Unix-API/pidfd/watchdog lifecycle; these locally tested controls do not
  establish live production isolation.
- a digest-frozen blinded-evaluation contract spanning eight target classes, four
  required lane kinds, provenance-bound external benchmark adapters, complete
  failure/cost/latency accounting, a ten-control Registry readiness policy, and a
  five-review release hold ledger. No live comparative result or launch approval is
  implied by the deterministic synthetic acceptance fixture.
- an authorization-gated real-browser vertical slice that launches a self-owned
  loopback website, drives Chrome through pinned Playwright MCP, records signed
  primary and reproduction traces, compares observable outcomes, and packages
  the evidence as a `.sova` capsule.

Read [ADR-0007](./docs/decisions/0007-topic-02-engineering-foundation.md),
[ADR-0008](./docs/decisions/0008-topic-03-domain-contracts.md), the
[shared contracts](./docs/contracts/README.md), and the
[experimental format specifications](./docs/specifications/README.md).

## Why SOVA

AI agents do more than generate text. They browse, execute commands, call MCP servers, use tools, read and write memory, retrieve private context, modify files, operate interfaces, and delegate work to other agents.

That creates a new security problem:

- A static scanner can inspect what a component **looks like**.
- A one-shot test can observe what it did **once**.
- A recorder can preserve what happened **afterward**.
- A benchmark can test a fixed scenario that may already be known.

But the failures that matter can hide behind a particular phrase, file, tool order, permission, memory state, invocation count, previous conversation, or combination of individually harmless components.

SOVA is being built to connect the entire security loop:

```mermaid
flowchart LR
    A["Map the real<br/>capability surface"] --> B["Drive the agent<br/>under hostile conditions"]
    B --> C["Search for hidden<br/>trigger conditions"]
    C --> D["Record every material<br/>action and observation"]
    D --> E["Seal a verifiable<br/>.sova-trace"]
    E --> F["Reproduce and<br/>replay the finding"]
    F --> G["Reconstruct and test<br/>the likely cause"]
    G --> H["Share a portable<br/>.sova artifact"]
    H -. "regression" .-> B
```

SOVA is not intended to be another disconnected scanner or observability
dashboard. It is intended to become a shared evidence and experimentation layer
for AI development, evaluation, interpretability, incident analysis, behavioral
research, and security.

## The owl

**Sova** means **owl** in Serbian and is the transliteration of the Russian word **сова**.

The owl represents the product we want to build:

- watchful enough to see the entire system;
- patient enough to find behavior that stays dormant;
- precise enough to distinguish evidence from assumption;
- independent enough to let anyone verify the result.

## What SOVA is building

SOVA is organized around one always-on evidence substrate and a set of connected security verbs.

<table>
  <tr>
    <td width="14%" align="center"><strong>RECORD</strong></td>
    <td><code>sova trace</code> captures model, tool, MCP, memory, retrieval, process, browser, computer, and egress activity into a versioned <code>.sova-trace</code>.</td>
  </tr>
  <tr>
    <td align="center"><strong>DISCOVER</strong></td>
    <td><code>sova map</code> inventories agents, tools, skills, MCP servers, identities, permissions, approval gates, egress paths, and transitive capability reach.</td>
  </tr>
  <tr>
    <td align="center"><strong>TEST</strong></td>
    <td><code>sova check</code>, <code>detonate</code>, <code>compose</code>, <code>rehearse</code>, and <code>arena</code> exercise components and complete agents inside controlled environments.</td>
  </tr>
  <tr>
    <td align="center"><strong>EXPLAIN</strong></td>
    <td><code>sova forensics</code> reconstructs the run, identifies decision points, and evaluates causal hypotheses through controlled counterfactual re-runs.</td>
  </tr>
  <tr>
    <td align="center"><strong>PROVE</strong></td>
    <td><code>sova verify</code>, <code>replay</code>, and <code>evidence</code> turn observations into reproducible, redaction-aware evidence—not unsupported assurance.</td>
  </tr>
  <tr>
    <td align="center"><strong>WATCH</strong></td>
    <td><code>sova sentinel</code>, behavioral <code>diff</code>, and CI regression testing detect when a model, component, permission, or tool update changes security behavior.</td>
  </tr>
  <tr>
    <td align="center"><strong>SHARE</strong></td>
    <td><code>sova registry</code>, <code>adjudicate</code>, and <code>disclose</code> make findings portable, reviewable, responsibly publishable, and independently reproducible.</td>
  </tr>
</table>

### The headline capability: find the sleeper

A component may behave safely for hundreds of runs and activate only when:

- a particular word appears;
- a file exists;
- the invocation counter reaches a threshold;
- the agent has accumulated a specific memory;
- one tool has already been called;
- the environment contains a particular secret or permission;
- an individually benign component is combined with another.

SOVA plans to search this **conditional-trigger space** systematically rather than running only a fixed attack list.

The public claim will be earned experimentally: SOVA must repeatedly find confirmed behavior that strong baselines miss before we say that it does.

### `.sova` — a portable AI-behavior capsule

A `.sova` file is now implemented experimentally as an open, versioned,
inert-by-default capsule that can organize:

- a portable scenario or replay recipe;
- triggers, parameters, preconditions, environment, and dependencies;
- agents, models, tools, protocols, and runtime versions;
- `.sova-trace` records and content-addressed artifacts;
- assertions, evaluations, findings, and hypotheses;
- safety, authorization, limitations, disclosure, and cleanup information;
- authorship, provenance, integrity, licence, and citation information.

It supports security cases, evaluations, agent trajectories, behavioral
interpretability, incident forensics, and research publication. The minimum
capsule remains small: a manifest and one typed object. Rich traces and large
artifacts are optional.

Opening, inspecting, verifying, rendering, or migrating a capsule never runs
its scenario, installs tools, fetches URLs, or invokes a model. Controlled
re-execution is a separate, explicitly authorized operation.

### `.sova-trace` — the evidence record

A `.sova-trace` now experimentally carries:

- ordered events and causal relationships;
- model, tool, MCP, memory, retrieval, process, network, browser, and computer observations;
- target, environment, methodology, taxonomy, model, and executor fingerprints;
- attack, judge, oracle, reproduction, and forensic context;
- redaction metadata;
- artifact hashes;
- a standard signed envelope and offline verification path.

SOVA builds on open telemetry and signing conventions rather than inventing
private cryptography. Its claims are bounded by the published
[threat model](./docs/specifications/threat-model.md).

The accepted [capsule and trace decision](./docs/decisions/0009-sova-behavior-capsule-and-trace-model.md)
keeps scenarios, traces, findings, evaluations, reports, and registry entries
separately typed inside or alongside the outer capsule.

### Versioning without lock-in

The accepted [versioning and lossless-migration policy](./docs/decisions/0002-versioning-and-lossless-migration.md) is designed so a future SOVA release can continue reading every stable `.sova` version and migrate old artifacts forward without silent data loss.

The promise is deliberately precise:

- the original file is never overwritten by default;
- every source value, payload, attachment, ordering rule, oracle, and safety constraint is preserved;
- implicit old defaults become explicit equivalent values;
- future-only information that did not exist is marked `unknown`, never fabricated;
- unsupported required behavior fails closed;
- the migrated artifact keeps provenance to the original digest but receives its own digest and signature.

The current experimental local workflow is:

```bash
sova validate behavior.sova
sova inspect behavior.sova
sova migrate behavior-v001.sova behavior-v010.sova --to 0.1.0
```

SOVA will use experimental `0.x` schemas until real scenarios, migration rehearsals, independent implementations, and hostile-input tests justify `1.0.0`.

### Semantic reproduction

Hosted model execution is not reliably bit-for-bit deterministic. SOVA therefore separates:

1. **Trace playback** — inspect exactly what was recorded.
2. **Controlled re-execution** — rerun under pinned or equivalent conditions.
3. **Semantic reproduction** — test whether the same material security outcome recurs.

Instead of hiding nondeterminism, SOVA records repeated trials, condition drift,
and reproduction-rate evidence when those inputs are supplied.

## Capability map

```mermaid
mindmap
  root((SOVA))
    Evidence core
      .sova
      .sova-trace
      Signing
      Redaction
      Offline verification
      Semantic replay
    Discovery
      Agent inventory
      MCP inventory
      Tool and permission graph
      Transitive capability reach
      Tool-description integrity
    Adversarial testing
      Quick check
      Detonation
      Trigger search
      Genetic mutation
      Multi-turn sequences
      Composition testing
      Rehearsal
    Forensics
      Reconstruction
      Decision points
      Counterfactual re-runs
      Probabilistic attribution
      Scanner adjudication
    Continuous assurance
      Behavioral diff
      Sentinel
      CI regressions
      Model comparisons
    Community
      Registry
      Responsible disclosure
      Arena
      Leaderboard
      Extension SDK
```

## How the system fits together

SOVA owns the security method and evidence. Execution providers remain replaceable.

```mermaid
flowchart TB
    CLI["CLI / Local SOVA MCP / SDK"]
    CORE["SOVA OSS Core<br/>mapping • attack planning • trigger search • judging"]
    SAFE["Authorization and safety gate<br/>self-owned scope • blast radius • non-destructive defaults"]
    EXEC["ExecutorAdapter"]
    SCRIPT["ScriptedExecutor<br/>deterministic tests"]
    LOCAL["RestrictedLocalExecutor<br/>developer-only host execution"]
    MELRA["Optional MelraExecutorAdapter<br/>browser • computer • terminal"]
    CUA["Optional CUA Driver adapter<br/>bounded Windows computer"]
    SENSORS["SOVA sensor mesh and deterministic oracles"]
    TRACE[".sova-trace evidence substrate"]
    OUTPUT["verify • replay • forensics • evidence • registry"]

    CLI --> CORE
    CORE --> SAFE
    SAFE --> EXEC
    EXEC --> SCRIPT
    EXEC --> LOCAL
    EXEC --> PLAYWRIGHT["Playwright MCP"]
    EXEC --> WINDOWS["Windows-MCP"]
    EXEC --> MELRA
    EXEC --> CUA
    SCRIPT --> SENSORS
    LOCAL --> SENSORS
    PLAYWRIGHT --> SENSORS
    WINDOWS --> SENSORS
    MELRA --> SENSORS
    CUA --> SENSORS
    SENSORS --> TRACE
    TRACE --> OUTPUT
```

### MELRA (formerly Atlas MCP / Atlas OS)

[MELRA](https://github.com/XAGI-Lab/melra), created by Dheeraj S at [XAGI Labs](https://xagilabs.com), is implemented as an optional execution adapter for:

- browser use;
- computer use;
- terminal use.

SOVA does **not** outsource its containment admission, authorization, trigger search, observations, judging, redaction, signing, replay, forensics, or reporting to MELRA. The public capability broker works without MELRA through scripted and restricted-local executors, Microsoft Playwright MCP for browser use, and an explicitly restricted Windows-MCP adapter for optional desktop use.

MELRA is a separate XAGI Labs project, not SOVA Engine and not a source of TRUSCOR authority. Public SOVA integration will rely only on MELRA's public interface and reproducible behavior of a pinned public release; confidential Atlas/MELRA material is outside this repository.

The current MELRA `0.3.0-alpha.10` audit is intentionally split by capability.
SOVA's opt-in test passed computer capability inspection, an allowlisted
terminal command, installed-Chrome navigation to a self-owned loopback fixture,
and same-process cookie reuse. MELRA's Windows build command still ends on a
Unix-only `chmod`, and process-restart profile persistence is not claimed. SOVA
therefore recognizes only MELRA's exact planned `verified_success`, treats its
receipts as defense-in-depth input, and can remove MELRA without changing any
artifact or evidence contract.

SOVA also has a checksum-pinned optional [CUA Driver](https://github.com/trycua/cua)
`0.12.6` boundary. Bounded read-only live conformance passed, while effectful
desktop conformance remains unadmitted because UI Automation timed out and this
runner exposed no independently verifiable foreground desktop. See the
[external execution specification](./docs/specifications/external-execution-broker-0.1.md)
and [live validation record](./docs/engineering/external-executor-validation-2026-08-09.md).

## Implemented evidence, replay, rehearsal, and regression core

The pre-alpha now includes:

- four-state offline verification (`verified`, `partial`, `invalid`, and
  `unsupported`);
- three separately named replay operations: inert playback, fresh controlled
  re-execution, and repeated semantic reproduction;
- an evidence-native, XSS-safe replay application with play/pause, speed,
  sensor lanes, search, recorded-link navigation, synchronized comparison, and
  a bounded integrity-checked loopback live tail;
- explicit opt-in headed-browser WebM capture, typed visual-replay packaging,
  digest-bound decisive-oracle cueing, and one-step `sova replay FINDING.sova`
  rendering that selects the exact trace event and asks the operating system to
  open one inert self-contained local page with its duration-bounded decisive
  video window selected (`--no-open` renders without requesting a browser);
- numerator/denominator, Wilson uncertainty, condition sensitivity, and
  optional calibrated-judge reporting;
- a bounded MCP stdio client, pinned open-source launch recipes, capability
  routing, evidence normalization, and conservative fallback;
- a 13-dimension trigger-space model with independently measurable signature,
  random, grid, coverage, human, and adaptive baselines;
- deterministic minimization into portable `.sova` intent; and
- an owned-target-only Phantom Fuzzer contract with in-memory token zeroization.
- credential-stripped, substitute-only rehearsal with signed failure/success
  traces and digest-bound selective export;
- shell-free local process tracing, environment/behavior/methodology drift,
  local sentinel history, CI/SARIF output, and file-integrity self-checks; and
- a signed, content-addressed, offline registry with pull-only mirror caching
  and human-confirmed local contribution staging.
- a loopback self-hosted registry/leaderboard reference service with bounded
  staged uploads, pinned evidence signers, restart-safe verification, signed
  indexes, SSE updates, and no execution of submitted content;
- a contained consequential-action lab that creates a real disposable file,
  transfers email through loopback SMTP, posts to a loopback message sink,
  persists a disposable setting, repeats the effects, and packages signed
  traces plus browser video, replay, and a registry-ready module entry;
- a durable foreground monitor scheduler with non-executable job documents,
  overlap exclusion, restart recovery, retention, and signed drift evidence;
- an MCP `2025-11-25` stdio server whose offensive tools require exact,
  expiring, single-use human approval through a separate local control channel;
- a digest-pinned MCP manifest and `sova check --self` drift check, with
  checksum and GitHub/Sigstore provenance generation for release candidates;
- eight typed extension kinds, metadata-only PyPA discovery, digest-pinned
  interactive subprocess execution, signed evidence, and a bounded JSONL
  compatibility path that is explicitly not a security sandbox;
- credential-late OpenAI, Anthropic, OpenRouter, and loopback Ollama adapters,
  explicit role routing and model-swap envelopes, and no-network fake transports;
- eight target-manifest kinds and a provenance-preserving Inspect AI Sample
  JSON/JSONL bridge that reports conversion loss instead of executing setup;
- freshness/scope/nonce-bound probe verification, a deterministic local Arena
  with trace-and-capsule evidence per attempt, a static evidence-gated
  leaderboard, an inert CTF catalog, and redaction-first captioned Y4M clips.
- a real-time Arena chamber where one or several agents select exact declared
  environment actions while SOVA records filesystem, database, API, sink-only
  network, inter-agent, safety, authorization, state, and oracle events into
  the same signed trace exposed live; plus an authorized provider-backed
  website Arena lane.
- an adaptive semantic website Arena where a provider—or a conforming OCI
  planner when a registered, attested live gVisor host is available—can discover
  same-origin pages and build new plans from typed navigation, history, form,
  keyboard, pointer, drag, modal, and bounded tab primitives, while SOVA
  enforces independent budgets, exact batch approval, deterministic persisted
  oracles, clean reproduction, recordings, and decisive replay cues.
- a strict third-party agent protocol that conditionally admits exact
  digest-pinned images only through mandatory attested gVisor execution with no
  network, credentials, host mounts, writable root, capabilities, or
  container-engine socket; mandatory contract/failure-path tests pass, no
  ordinary-container fallback exists, and live use still requires a registered
  `runsc` host.
- an executor-backed browser swarm where bounded model roles take sequential
  turns over one target-bound opaque browser identity, share only redacted
  observations, and produce signed coordinator and participant traces plus a
  portable audit capsule; optional recording emits a byte-identical verified
  `swarm-finding.sova` for the first reproduced pass with duration-bound cues.
- a three-phase blinded causal-validation protocol with label-free frozen
  predictions, committed and optionally DSSE-pinned answer keys, stochastic
  CPU-only fixtures, abstention-aware metrics, and explicit external-study
  limits.

These are implemented engineering capabilities, not a claim that the current
generic search algorithm is novel or superior on real systems.

## Implemented capability surface

The following capability families are implemented experimentally at `0.1`.
Their validated depth differs by backend; the project-status table below names
the real-runtime evidence and every remaining external boundary.

### Discover

- Agent, sub-agent, skill, plugin, MCP server, and tool inventory.
- Declared, observed, and inferred capability graph.
- Identity, credential, permission, approval, and egress paths.
- Transitive “tools of tools” reach.
- Risk-classified attack-surface denominator.
- Tool-description and schema rug-pull detection.

### Test

- Sixty-second bounded component check with an explicit detection floor.
- Isolated detonation with synthetic secrets, files, databases, APIs, and services.
- Canary credentials and sink-only network honeypots.
- Multi-turn adversarial sequences.
- Conditional-trigger search across content, state, timing, invocation count, memory, filesystem, permission, and composition.
- Genetic/evolutionary mutation from successful and near-successful attempts.
- Composition testing for emergent chains.
- Safe rehearsal of real tasks against credential-stripped environment clones.
- Standard comparable profile and fully customizable non-comparable profile.

### Observe and judge

- Deterministic file, process, network, tool, permission, page, API, database, and canary oracles.
- Memory, retrieval, MCP, inter-agent, browser, and computer sensors.
- Independent Attacker and Judge roles.
- Rule and deterministic evidence before model judgment.
- Inconclusive and uncertainty states instead of forced verdicts.
- Adversary-effort metrics: turns, tokens, time, attempts, and mutations to success.

### Explain

- Cross-layer timeline reconstruction.
- Decision-point highlighting.
- Competing causal hypotheses.
- Counterfactual reruns with one candidate layer changed.
- Probabilistic attribution to model, prompt, orchestration, tool, permission, memory, handoff, or environment.
- Explicit sensor gaps and confounding factors.

### Prove and reproduce

- Portable adversarial scenarios.
- Signed, timestamped, redaction-aware traces under a stated threat model.
- Offline verification.
- Controlled re-execution.
- Semantic reproduction rate.
- Technical evidence packages with methodology and taxonomy versions.
- Self-assessment watermarking—never a self-issued certificate.

### Watch and share

- Behavioral regression diffing.
- Local sentinel runs.
- Durable scheduled local snapshot monitoring with signed result traces.
- CI policy and pull-request evidence.
- Offline/operator-publishable, mirrorable registry of reviewed `.sova` artifacts.
- Self-hosted loopback staging, verification, event, and leaderboard service.
- Execution-based scanner adjudication.
- Coordinated disclosure workflow.
- Reproducible component and model leaderboard.
- Local Arena and CTF modes.
- Captioned replay clips linked to verifiable artifacts.

## The developer experience

The intended workflow is deliberately small:

```bash
# Implemented local commands

# Discover local capability reach without executing target code
sova map ./my-agent --output ./my-agent.sova-map.json

# Exit 1 means the bundled planted behavior was confirmed
sova check synthetic-sleeper ./sova-check
# Or check an owned/controlled browser target with a finite non-offensive campaign:
sova check target.json ./browser-check --browser-campaign campaign.json

# Run the complete zero-configuration proof
sova demo sleeper ./sova-demo

# Verify, inspect, compare, and visualize evidence without executing it
sova verify ./run.sova-trace
sova playback ./run.sova-trace
sova replay modes
sova replay timeline ./run.sova-trace ./replay.html \
  --comparison ./fresh-run.sova-trace --media ./browser-session.webm
sova replay ./evidence.sova
# Automation can derive the same HTML without launching a browser:
sova replay ./evidence.sova --no-open
# The explicit destination-preserving interface remains available:
sova replay capsule ./evidence.sova ./capsule-replay.html
sova replay serve ./run.sova-trace --duration-seconds 30
sova replay study ./run.sova-trace ./trial-1.sova-trace ./trial-2.sova-trace

# Inspect pinned external-backend receipts and run the inert search comparison
sova executors receipts
sova hunt-demo

# Reconstruct observable evidence and assess reviewed paired interventions
sova forensics reconstruct ./incident.sova-trace
sova forensics attribute ./counterfactual-study.json
sova forensics browser-counterfactual ./target.json ./browser-study.json ./cf-output
sova forensics benchmark
sova forensics blind-fixture ./task.json ./.sova/private/answer-key.json
sova forensics blind-run ./task.json ./predictions.json
sova forensics blind-score ./task.json ./predictions.json ./.sova/private/answer-key.json ./score.json

# Build watermarked self-assessment evidence and interoperable SARIF
sova evidence ./evidence.json --format technical
sova evidence ./evidence.json --format sarif

# Turn one linked signed trace/capsule into a complete offline review workspace
sova case build ./run.sova-trace ./finding.sova ./case-workspace

# Prepare an inert scanner test plan, then evaluate reviewed observations
sova adjudicate plan ./adjudication-study.json
sova adjudicate evaluate ./adjudication-study.json

# Prepare a local disclosure package; this never sends or publishes
sova disclose ./disclosure-study.json

# Plan component-chain candidates without execution, or evaluate supplied observations
sova compose plan ./composition-graph.json --strategy trigger-aware-sequence
sova compose evaluate ./composition-study.json --strategy trigger-aware-sequence

# Prepare, run, review, and selectively stage a credential-free rehearsal
sova rehearse prepare ./my-agent ./rehearsal
sova rehearse run ./rehearsal-task.json ./rehearsal ./task.sova-trace ./report.json
sova rehearse agent-run ./provider-request.json ./provider-runtime.json ./rehearsal ./agent-run --allow-provider-calls
sova rehearse export ./report.json ./rehearsal ./accepted --approve sha256:CHANGE_ID

# Freeze and compare behavior, then run local/CI gates
sova trace command ./run.sova-trace --working-directory ./owned-workspace -- /absolute/executable ARG
sova trace snapshot ./baseline.json --output ./baseline.snapshot.json
sova trace snapshot ./current.json --output ./current.snapshot.json
sova diff ./baseline.snapshot.json ./current.snapshot.json
sova sentinel ./baseline.snapshot.json ./current.snapshot.json ./history.jsonl
sova monitor serve ./monitor.json ./.sova-monitor --workspace ./observations --once
sova ci ./baseline.snapshot.json ./current.snapshot.json --sarif ./sova.sarif

# Run the local engineering lab and inspect honest stable-release blockers
sova acceptance run ./acceptance-output
sova acceptance evaluate ./external-receipts

# Verify a protected local file baseline
sova self-check create . ./integrity.json --include pyproject.toml
sova self-check verify . ./integrity.json

# Verify/cache an offline registry mirror and stage a reviewed contribution
sova registry verify ./registry --trusted-key-id sha256:EXPECTED_KEY
sova registry init-service ./.sova-community/service.token
sova registry prepare-upload ./metadata.json ./case.sova ./case.sova-trace \
  ./upload.json --kind leaderboard
sova registry serve ./.sova-community/data \
  --token-file ./.sova-community/service.token \
  --trusted-key-id sha256:EXPECTED_EVIDENCE_SIGNER \
  --methodology ./arena-methodology.md
sova sync ./registry --cache ./.sova-registry-cache
sova contribute ./contribution.json ./contribution-staging --confirm

# Verify the installed MCP tool surface against its release pin
sova check --self

# Inspect the local MCP manifest without starting a server
sova mcp manifest

# Run the deterministic local Arena and build verifiable community artifacts
sova arena run ./arena.json ./arena-output
# Or run provider-capable agents in the fully observed synthetic message Arena.
sova arena agent-run ./agent-arena.json ./agent-arena-output --allow-provider-calls
# Run agents against an instrumented synthetic environment and stream the
# canonical signed-trace event sequence while the match is running.
sova arena chamber ./examples/arena/chamber.json ./arena-chamber-output \
  --authorize-contained-fixture --stream-jsonl
# Run isolated provider roles against one exactly authorized website. Every
# generated browser batch still requires fresh human approval.
sova arena web ./website-target.json ./browser-campaign.json ./provider-runtime.json \
  ./arena-web-output --control-proof ./control-proof.json \
  --allow-provider-calls --stream-jsonl --headed --record-video \
  --playwright-browser-cache ./.cache/playwright-browsers
sova replay ./arena-web-output/browser/discovery.sova
# Let one planner adaptively discover and traverse a multi-page same-origin UI.
# The model can invent plans from typed actions, but each complete batch remains
# separately approved and only a fresh reproduced oracle can confirm a finding.
sova arena explore-web ./website-target.json ./semantic-browser-mission.json \
  ./provider-runtime.json ./arena-explore-output \
  --control-proof ./control-proof.json --allow-provider-calls \
  --allow-target-observation-disclosure --headed --record-video \
  --playwright-browser-cache ./.cache/playwright-browsers
sova replay ./arena-explore-output/discovery.sova
# Run several bounded roles over one operator-prepared, target-bound browser
# profile. Scripted roles need no provider-call flag.
sova arena swarm-web ./website-target.json ./browser-campaign.json \
  ./examples/arena/browser-swarm.json ./arena-swarm-output \
  --browser-profile-vault ./.sova/browser-profiles \
  --browser-profile-handle profile:0123456789abcdef0123456789abcdef \
  --headed --record-video \
  --playwright-browser-cache ./.cache/playwright-browsers --stream-jsonl
sova replay ./arena-swarm-output/swarm-finding.sova
sova leaderboard build ./leaderboard.json ./leaderboard-output
sova ctf build ./ctf.json ./ctf-catalog.json
sova replay clip ./clip.json ./replay.y4m

# Discover without importing code, prepare an exact local launch, then run it
# only after reviewing and typing the digest-bound approval phrase
sova extension discover
sova extension prepare ./manifest.json ./launch.json --executable /absolute/python --working-directory /absolute/example --argument /absolute/example/safe_oracle.py
sova extension run ./manifest.json ./launch.json ./extension-output

# Attest and conform a third-party agent image before granting it any SOVA role.
sova safety attest-gvisor --docker docker --image repo/agent@sha256:...
sova agent conform-oci ./oci-agent-runtime.json ./agent-conformance --docker docker

# Issue and verify a signed, nonce-bound probe response offline
sova probe issue ./probe-issuance.json ./response.json
sova probe verify ./response.json --nonce REQUEST_NONCE --scope manifest --key-id sha256:...

# Initialize and diagnose account-free local state
sova init ./.sova-state --provider none
sova doctor ./.sova-state

# Generate and verify release and cross-implementation evidence
sova release sbom uv.lock ./dist/sova-oss.cdx.json --scope runtime
sova release cargo-sbom deploy/worker/network-mediator/Cargo.lock ./dist/sova-network-mediator.cdx.json --root sova-network-mediator
sova release checksums ./dist ./dist/SHA256SUMS
sova release verify-checksums ./dist ./dist/SHA256SUMS
# Create receipt keys, sign strict evidence documents, then recompute one inert
# exact-candidate launch verdict. Pin the reviewed trust-policy digest out of band.
sova release keygen ./private.key ./public.key
sova release sign-evidence ./receipt.json ./private.key ./public.key ./receipt.dsse.json
sova release assemble-evidence ./trust-policy.json ./protocol.json ./observations.dsse.json ./registry-policy.json ./candidate.json ./launch-bundle.json --operational-receipt ./operation.dsse.json --review-receipt ./review.dsse.json --gate-receipt ./gate.dsse.json
sova release dossier ./launch-bundle.json ./dist/SHA256SUMS ./docs/research/claims-register.md ./public-claims-snapshot.json ./launch-dossier.json --expected-commit COMMIT --expected-trust-policy-digest sha256:...
sova conformance export ./sova-conformance-0.1.zip
sova conformance verify ./sova-conformance-0.1.zip

# Plan an authorized website/software assessment without connecting to it
sova target browser-kit https://owned.example ./owned-browser-kit
sova target template browser-agent ./website-target.json
sova target validate ./website-target.json
sova target plan ./website-target.json ./website-plan.json

# Build a secret-free composite profile and map supplied target materials.
# Intake never executes package code or silently upgrades inference to evidence.
sova target profile-create owned-app ./target-profile.json \
  --kind web --kind api --authorization-scope owned-lab \
  --material api=openapi=supplied=openapi.yaml \
  --entrypoint web=url=web=https://owned.example
sova target profile-validate ./target-profile.json
sova target intake ./target-profile.json ./intake --material api=./openapi.yaml

# Compile a bounded methodology; the plan does not itself authorize execution.
sova methodology library-export ./playbook-library.json
sova methodology policy-create ./target-profile.json ./methodology-policy.json
sova methodology compile ./target-profile.json ./methodology-policy.json \
  ./methodology-plan.json --intake-report ./intake/intake-report.json

# Inspect adapter contracts and normalize captured output offline.
# These commands never install or execute the upstream tool.
sova adapter catalog ./adapter-catalog.json
sova adapter describe adapter.nuclei ./nuclei-adapter.json
sova adapter plan adapter.nuclei ./nuclei-plan-template.json
sova adapter normalize adapter.nuclei ./invocation.json ./nuclei.jsonl \
  ./normalized.json --executable-digest sha256:EXACT_RUNTIME_DIGEST

# Validate the complete measurement pipeline on self-owned deterministic fixtures
sova target fixture website ./website-fixture
sova target fixture software ./software-fixture

# Exercise a real browser against SOVA's self-owned loopback website.
# Every run displays its closed action set and requires an exact approval phrase.
# Each approved action then consumes a distinct signed one-use token.
# Install the pinned Playwright FFmpeg runtime once as documented in
# docs/guides/authorized-target-testing.md before adding --record-video.
sova detonate owned-web-fixture ./live-browser-proof --headed --record-video \
  --playwright-browser-cache ./.cache/playwright-browsers

# Prove consequential agent actions in the resettable owned action lab.
# The recording visibly follows file, SMTP, message, settings, and proof views;
# no external account, recipient, host path, or network service is reachable.
sova detonate action-lab ./action-lab-proof --headed --record-video \
  --playwright-browser-cache ./.cache/playwright-browsers

# Exercise a real local process against two clean copies of SOVA's owned fixture.
# The exact actions and host-process limitations require a human approval phrase.
sova detonate owned-software-fixture ./live-software-proof

# Run the same bounded process/output/workspace-delta workflow for trusted
# software you own or are explicitly authorized to assess.
sova detonate software ./software-target.json ./scenario.sova ./source-workspace \
  ./software-proof --executable /absolute/path/to/trusted-program

# For an external website you own, first edit a browser-agent target manifest.
sova target challenge ./website-target.json ./website-challenge.json
# Host the emitted token at its exact proofUrl, then verify it without redirects.
sova target prove ./website-target.json ./website-challenge.json ./website-proof.json
sova detonate browser ./website-target.json ./scenario.sova ./website-proof \
  --control-proof ./website-proof.json --headed --record-video \
  --playwright-browser-cache ./.cache/playwright-browsers

# If the controlled target requires login, provision an opaque profile bound
# to the exact targetDigest, then complete login/CAPTCHA yourself in a headful
# browser. SOVA never receives credentials or exports the browser profile.
sova session browser-create ./.sova/browser-profiles operator TARGET_DIGEST
sova session browser-handoff ./website-target.json https://owned.example/login \
  ./.sova/browser-profiles PROFILE_HANDLE ./browser-handoff \
  --control-proof ./website-proof.json

# Search multiple reviewed interactions through a real browser, capture
# snapshot/screenshot-digest/console/network sensors, reproduce success, and
# package discovery.sova.
sova hunt owned-web-fixture ./live-browser-hunt
sova hunt browser ./website-target.json ./browser-campaign.json ./website-hunt \
  --control-proof ./website-proof.json \
  --browser-profile-vault ./.sova/browser-profiles \
  --browser-profile-handle PROFILE_HANDLE

# Optionally let tool-isolated model roles propose the bounded candidate set.
# Provider calls and the resulting exact browser-action batch are authorized separately.
sova hunt agent-browser ./website-target.json ./browser-campaign.json \
  ./provider-runtime.json ./website-agent-hunt \
  --control-proof ./website-proof.json --allow-provider-calls

# Adapt the next finite batch from deterministic prior-round evidence. Every
# round receives fresh exact approval; raw target content is not fed back.
sova hunt adaptive-browser ./website-target.json ./browser-campaign.json \
  ./adaptive-browser-policy.json ./provider-runtime.json ./website-adaptive-hunt \
  --control-proof ./website-proof.json --allow-provider-calls

# Live offensive MCP operations require a separately issued approval
sova mcp init-control ./control.key

# Launch broader live-target rehearsal only after a stronger admitted backend
sova rehearse prepare ./authorized-target ./isolated-workspace
```

The Internet-facing community blueprint uses the shipped SOVA image recipe and
the mandatory `preflight.py build`, `check`, and `up` path. It rejects mutable
image references, validates Compose's fully resolved image set, keeps operator
secrets in an absolute directory outside the checkout, and repairs the named
data volume plus stages the protected token into a separate read-only runtime
volume for the non-root service before startup. Follow the exact
[community deployment boundary](./deploy/community/README.md); this blueprint
is not a production-hosting attestation.

### Is the registry “Metasploit for AI security”?

That is the product direction, not a current equivalence claim. A registry
entry can already distribute a content-addressed `.sova` scenario or finding,
its reproduction metadata, taxonomy, provenance, licence, verification tier,
and signed evidence. The contained action lab now emits the first concrete
registry-ready action module and builds a verified signed local registry
snapshot containing it. Unlike a raw exploit collection, the registry never
executes submissions: secret scanning, safety validation, human review,
disclosure state, exact authorization, and evidence verification stay mandatory.

The remaining gap to a defensible “Metasploit-like” description is breadth:
maintained modules for real agent/tool ecosystems, independent reproduction,
moderation operations, and a deployed public service still require evidence.

One safe implemented demonstration is available now:

```bash
# No model, provider key, network, MELRA, container, or native target is required.
# The canonical package includes the cryptographic signing dependency.
sova demo sleeper ./sova-demo
sova verify --require-signature ./sova-demo/discovery/synthetic-sleeper.sova-trace
sova playback ./sova-demo/discovery/synthetic-sleeper.sova-trace
sova verify ./sova-demo/discovery/synthetic-sleeper.sova
```

It activates a deterministic planted sleeper, observes an inert run-unique
canary and a sink-only egress attempt, records authorization and containment,
evaluates deterministic oracles, resets the synthetic world, and produces an
offline-verifiable `.sova-trace` and `.sova` capsule, then performs a fresh
reproduction and exact declared-outcome comparison. It is a measurement-system
fixture, not evidence that a real model or host sandbox is safe. An arbitrary
local directory is currently mapped and reported `inconclusive`; SOVA will not
execute it without a selected authorized adapter.

The target experience:

- one install;
- one locally stored model configuration;
- no SOVA account;
- no mandatory SOVA server;
- no silent telemetry;
- local or user-chosen model inference;
- cached registry and local-model support for air-gapped environments.

## Built for different users

<table>
  <tr>
    <th>Developer</th>
    <th>Security engineer</th>
    <th>Researcher</th>
    <th>Platform / compliance team</th>
  </tr>
  <tr>
    <td>Check a component before installation and catch behavioral regressions in CI.</td>
    <td>Map capability reach, detonate safely, hunt triggers, and reconstruct incidents.</td>
    <td>Replace bespoke harnesses with portable scenarios, traces, repeated trials, and publishable artifacts.</td>
    <td>Generate versioned technical evidence from the same traces produced during testing.</td>
  </tr>
</table>

## Safety by construction

SOVA is a dual-use security project. Safety cannot be a disclaimer placed after implementation.

The intended controls are:

- **Self-owned scope by default.**
- **Proof of control**, not a URL assertion.
- **Explicit out-of-band human authorization for every offensive MCP invocation.**
- **Disposable isolation** for detonation.
- **Synthetic credentials and data** instead of production secrets.
- **Sink-only network behavior** for suspected-malicious components.
- **Non-destructive proof by default.**
- **Separate authorization for irreversible effects.**
- **Blast-radius, time, process, network, file, token, and mutation limits.**
- **Coordinated disclosure before naming affected components.**
- **No autonomous patching or pull requests.**
- **No claim that a bounded search proves universal safety.**

> [!WARNING]
> The local MCP exposes `detonate`, `rehearse`, and `probe` only through the
> exact-gated path. Each invocation requires an expiring, single-use approval
> created through a separate local control channel. This is authorization
> enforcement, not proof that the chosen live target or containment backend is safe.

## What SOVA will not claim

A short test cannot prove an agent safe. A sandbox cannot guarantee that it triggered every environment-gated behavior. An unbounded trigger space cannot be searched completely.

SOVA will publish its detection floor, including:

- anti-sandbox behavior;
- conditions absent from the synthetic environment;
- very-long-fuse activation;
- unsupported internal state;
- model and provider nondeterminism;
- bounded search horizon;
- incomplete sensors;
- probabilistic causal attribution.

The output should say what was observed, under which conditions, for how long, and with what uncertainty.

## Research programme

SOVA is intended to produce both software and reproducible research.

The principal research directions are:

1. Conditional-trigger search for black-box agent components.
2. Execution-based adjudication of scanner disagreement.
3. Counterfactual fault attribution for agent-security incidents.
4. Portable `.sova` artifacts and semantic reproduction rates.
5. Model-swap vulnerability transferability.
6. The limits of agent detonation.
7. Redaction-preserving verifiable evidence.
8. A unified sensor mesh for memory, retrieval, MCP, and inter-agent state.
9. Provenance-separated capability closure against declared and runtime graph baselines.
10. Evidence-firewalled adjudication against transcript-level judge injection.

Research claims will require predeclared protocols, strong baselines, repeated trials, ground truth, uncertainty, ethics review, and reproducible artifacts. Paper and patent decisions will be made before irreversible public disclosure.

The Topic 01 evidence controls are now public:

- the [claims register](./docs/research/claims-register.md) records what is verified, provisional, unverified, retired, or still a value hypothesis;
- the [prior-art and interoperability matrix](./docs/research/prior-art-and-interoperability.md) records what SOVA will build, integrate, import, interoperate with, or deliberately skip;
- the [predeclared comparison protocol](./docs/research/predeclared-comparison-protocol.md) freezes the target classes, strong baselines, budgets, objective oracles, repeated trials, false-positive rules, and evidence gates before results exist;
- the [publication and IP review](./docs/governance/publication-and-ip-review.md) prevents vulnerability, invention, private-data, and unsupported-claim disclosure.

The current comparative result is **NOT RUN - UNPROVEN**. SOVA therefore makes no present claim that it catches defects other tools miss or attributes failures correctly. Those statements must be earned against the frozen protocol.

## Project status

| Area | Status |
|---|---|
| Vision and scope | Defined |
| Public identity and README | Active |
| Canonical artifact meanings | ADR-0001 superseded by the expanded [ADR-0009](./docs/decisions/0009-sova-behavior-capsule-and-trace-model.md) |
| `.sova` capsule meaning and migration invariants | Accepted in [ADR-0009](./docs/decisions/0009-sova-behavior-capsule-and-trace-model.md) and [ADR-0002](./docs/decisions/0002-versioning-and-lossless-migration.md) |
| Open/private and SOVA Engine boundary | Accepted in [ADR-0003](./docs/decisions/0003-open-source-and-proprietary-boundary.md) |
| Self-assessment and TRUSCOR authority boundary | Accepted in [ADR-0004](./docs/decisions/0004-self-assessment-and-truscor-boundary.md) |
| Topic 00 project constitution | Accepted in [ADR-0005](./docs/decisions/0005-topic-00-project-constitution.md) |
| Topic 01 claims, prior art, experiment, and publication decision | Accepted in [ADR-0006](./docs/decisions/0006-topic-01-evidence-go-no-go.md) |
| Topic 02 repository, language, quality, documentation, and public-safety foundation | Implemented in [ADR-0007](./docs/decisions/0007-topic-02-engineering-foundation.md) |
| Topic 03 shared vocabulary, lifecycle, taxonomy, coverage, and version contracts | Implemented in [ADR-0008](./docs/decisions/0008-topic-03-domain-contracts.md) |
| Comparative evidence gates 01-A and 01-B | **Not run - unproven; comparative claims prohibited** |
| Local `sova` format CLI | Implemented experimentally: template, pack, validate, lint, inspect, hash, compatibility, migrate, verify, query, playback, compare, export, recover |
| `sova.contracts` Python API | Implemented and experimental at `0.1.0` contract level |
| Python package and locked contributor environment | Implemented as `sova-oss` / `uv.lock`; not published to PyPI |
| Cross-platform CI and quality/security gates | Implemented |
| Public repository boundary check | Active in CI and locally |
| Repository licence | [Apache License 2.0](./LICENSE) |
| Trademark and fork naming | [SOVA-OSS policy active](./TRADEMARKS.md) |
| Dual-use and coordinated disclosure | [Policies active](./DUAL_USE_POLICY.md) |
| `.sova` capsule and scenario schemas | Experimental `0.1.0` implemented with safe package tooling |
| `.sova-trace` experimental contract | Experimental `0.1.0` implemented with streaming writer and offline verifier |
| Scripted/local/isolated execution | Experimental executor contract and no-Atlas vertical slice implemented; local host execution is explicitly not a security sandbox. Docker Desktop and gVisor `runsc` backends require exact digest-pinned cached Linux images, no network/host mounts/daemon socket, non-root execution, bounded resources, post-run inspection, and cleanup. The OCI agent adapter additionally requires read-only root, no credentials, strict JSON protocol binding, exact human authorization, and signed conformance evidence. gVisor reduces direct host-kernel exposure but is not a separate VM; its live lane still requires a registered `runsc` runner |
| Authorization and containment | Experimental ACE kernel, closed exact-batch human review, per-action signed one-use tokens, effect budgets, proof-of-control validation, and backend admission implemented |
| Synthetic detonation and sensors | Event-sourced fake world, inert canaries, sink-only collector, deterministic oracles, nine ground-truth target families, and a claim-conditioned sensor ledger covering direct/provider/derived/unavailable modes, drops, clock domains, ordering, and blind spots; total observability is explicitly denied |
| `sova map` | Air-gapped typed inventory, provenance-separated reach closures, map schema, and tool-definition drift implemented in [ADR-0013](./docs/decisions/0013-provenance-separated-capability-map.md) |
| SOVA Runtime | Provider-neutral isolated roles, standard/custom profiles, evidence firewall, local minimized experience, opaque sessions, and verified executor fallback implemented in [ADR-0014](./docs/decisions/0014-evidence-firewalled-runtime.md) |
| External security-tool adapters | Twelve promoted version-pinned normalizers (ZAP, Nuclei, Schemathesis, PyRIT, garak, promptfoo, Trivy, Syft, Grype, OSV-Scanner, Gitleaks, Semgrep), constrained ffuf/httpx/testssl/sqlmap/mitmproxy/zgrab2 and generic MCP/HTTP descriptors, and an enforced Nmap legal hold. Runtime execution requires operator-supplied SHA-256-bound bytes, exact version evidence, target authority, containment, config/rules pins, and disclosure approval for external transfer. Owned fixtures validate routing, normalization, trace binding, failure separation, reproduction comparison, and cleanup; live compatibility with every upstream binary and production isolation remain deployment evidence, not repository claims |
| Universal target intake and methodology | Eight-class target profiles, workflow/surface graphs, explicit discovery gaps, bounded collectors, deterministic methodology compilation, 74 native playbooks, and non-authorizing execution plans are implemented. Intake is evidence about supplied and observed surfaces, not proof that every workflow or attack surface was discovered |
| Oracle laboratory and coverage | Proposal, calibration, promotion, differential/metamorphic, independent-reproduction, and eight-dimensional measured-coverage contracts are implemented. The deterministic local study validates the machinery only; target-specific oracle reliability and exhaustive vulnerability discovery remain unproven |
| Production worker control plane | Immutable controller/worker messages, content-addressed inputs, secret capabilities, hostile-evidence extraction, cleanup/attestation receipts, an exact Firecracker launch compiler plus root-only Unix-API/pidfd/watchdog lifecycle, and a separately pinned static Rust network mediator are implemented. The mediator passed the current locked RustSec audit, was byte-reproducible locally and WSL-smoke-tested, and is included in candidate SBOM/checksum/signing/provenance; `process-exited` is not a guest verdict. No Firecracker workload has run on an attested dedicated Linux/KVM worker in this release evidence, so production-grade hostile-agent isolation is not claimed |
| Blinded validation and launch gates | An eight-target-class/four-lane evaluation protocol, provenance-bound candidate benchmark adapters, exact run accounting, Registry readiness policy, local backup/recovery utility, five-review release ledger, deterministic evidence assembler, and signed exact-candidate launch dossier are implemented. The dossier verifies role-scoped DSSE receipts against an out-of-band pinned trust policy, enforces distinct role keys and structural independent-review separation, recomputes every nested verdict, exposes machine-readable evaluation/Registry/review/external-gate summaries and hold reasons, binds the actual artifact manifest and claims-register bytes, and never publishes automatically. Live providers, blinded licensed targets, matched baselines, dedicated-worker evidence, public Registry operations, independent/legal/security reviews, and publication remain open |
| `sova check` | Bundled synthetic and authorized live-browser checks with finite candidate sets, exact human approval, signed traces, controlled reproduction, and honest confirmed/not-observed/inconclusive states |
| `sova detonate` | Real Playwright/Chrome website execution plus bounded trusted local-process execution on two credential-stripped copies; both require exact human approval and produce signed primary/reproduction traces plus evidence capsules. Browser detonation supports explicit opt-in headed WebM recording packaged as typed visual replay and rendered directly from the capsule. A four-class static/SPA/authenticated/popup owned-site matrix passed real Chrome. The contained action lab adds real disposable file, loopback SMTP email, loopback message, and settings effects with independent ground-truth receipts and a registry-ready module; this proves the controlled vertical, not arbitrary third-party agents. Windows/macOS Appium and Linux AT-SPI application-bound adapters exist at the executor API, but general native-desktop detonation still requires platform drivers, owned fixtures, and CLI integration |
| `sova hunt` | Bounded operator-authored or provider-assisted candidate search executes in real Playwright/Chrome, records snapshot/console/network observations, detects near misses, reproduces the winning recipe under fresh approval, and emits signed traces plus an offline-verifiable discovery capsule. Deterministic tests verify isolated roles; one founder-authorized OpenRouter free-model run against loopback AI Goat Challenge 1 passed with controlled reproduction and digest-bound exact-moment video evidence on 2026-08-20. The expanded nine-mission semantic AI Goat lane—including Knowledge Base workflows—is implemented and statically preflighted, but the final OpenRouter availability probe returned `SOVA-PROVIDER-RATE-LIMIT`, so the all-nine campaign was not launched and is not claimed as passed. This is not general target coverage or provider-quality evidence; see the [bounded acceptance record](./docs/engineering/aigoat-loopback-acceptance-2026-08-20.md) |
| Persistent browser sessions | Exact-target-bound opaque profiles, cross-process exclusive leases, bounded stale recovery, manual headful authentication/CAPTCHA handoff, campaign reuse, and installed-Chrome two-process fixture persistence are implemented; profile state remains sensitive local executor material, is not SOVA-encrypted, and is never embedded in capsules or traces |
| MELRA/CUA adapters | MELRA `0.3.0-alpha.10` browser/terminal/computer probe and same-process session reuse passed live; checksum-pinned CUA `0.12.6` bounded reads passed, while live desktop mutation remains visibly blocked on this runner |
| Sleeper demonstration | Implemented with named narrow baselines, two-dimensional search, signed discovery/reproduction traces, `.sova`, independent offline verification, and reset evidence |
| `sova forensics` | Evidence-linked reconstruction, reviewed-trial attribution, repeated authorized real-browser message-removal interventions, and a strict blinded task/prediction/score protocol with commitment and optional reviewer-key verification; the bundled stochastic study passes its declared software-validation gates, while real-system causal accuracy and reviewer independence remain externally unproven |
| `sova case build` | Exact trace/capsule binding plus one offline forensic, replay, evidence, monitoring, and blocked contribution-preview workspace; no re-execution, network, upload, or automatic disclosure |
| `sova evidence`, `adjudicate`, and `disclose` | Watermarked evidence, SARIF projection/import, bounded scanner labels, human-gated local disclosure preparation, and four report views implemented in [ADR-0020](./docs/decisions/0020-bounded-evidence-adjudication-disclosure.md) |
| `sova compose` | Typed metadata-only graph, four bounded search strategies, fresh-evidence minimization, element-removal attribution, portable capsule fragment, and deterministic composition-only fixture implemented in [ADR-0021](./docs/decisions/0021-bounded-composition-only-search.md); comparative search superiority remains unproven |
| `sova rehearse` | Credential-stripped substitute workspace, distinct user/attacker evidence, signed traces, review, and selective export implemented in [ADR-0022](./docs/decisions/0022-substitute-only-rehearsal-and-selective-promotion.md); the built-in backend is not a security sandbox |
| `sova trace`, `diff`, `sentinel`, `monitor`, `ci`, and `self-check` | Deterministic local recorder, three-axis drift, one-shot sentinel/CI, and a durable scheduler with workspace-bound jobs, OS overlap exclusion, restart recovery, bounded retention, signed traces, and an HTTPS HMAC/idempotency/acknowledgement alert adapter. Service-manager templates ship for Linux, macOS, and Windows; remote collection, remediation, HA, and uptime remain deployment claims |
| Registry, `sync`, adapters, `contribute`, and self-hosted community service | Offline content-addressed registry plus a loopback service with token-gated bounded staging, signer-pinned asynchronous verification, atomic promotion, signed live index, SSE events, standard-profile leaderboard, and an exact endpoint/key-digest health contract. The documented container/Caddy launch path requires immutable-image preflight, exact equality between resolved Compose images and the two validated digest references, validation and protected staging of external operator inputs, and persistent-volume ownership repair before the non-root, read-only-root, capability-dropped service starts. This is a deployment blueprint, not a hosted or production-attested community; operator identity policy, moderation, backups/restore drills, abuse controls, monitoring, incident response, independent review, and uptime evidence remain external gates |
| Local MCP | MCP `2025-11-25` stdio, safe tools, three exact-gated tools, out-of-band human approval, manifest pin, and self-check implemented in [ADR-0025](./docs/decisions/0025-local-mcp-out-of-band-authorization.md) |
| Extension SDK, providers, targets, interoperability | Experimental fail-closed contracts, import-free discovery, machine-local digest-pinned preparation, exact human-approved subprocess execution, a preregistered paired provider/model experiment matrix, Python and Node offline verifiers, a no-network conformance kit, and a strict OCI agent protocol with signed `describe`/`self-test`/`respond` conformance. Ordinary extension host execution is not a sandbox; external implementation ownership, provider transferability, and adoption remain unproven |
| Probe, Arena, leaderboard, CTF, replay media | Deterministic standard-profile Arena, provider/OCI-capable message Arena, real-time sensor-instrumented multi-agent chamber, authorized provider-backed website Arena, adaptive multi-page semantic website exploration, and browser-swarm lanes are implemented with signed observable evidence. Installed-Chrome validation on a controlled loopback fixture covers semantic navigation, history, forms, drag, modal handling, bounded tabs, clean reproduction, video, and exact-moment replay. The prepared all-nine AI Goat provider campaign remains unrun because the final availability probe was rate-limited. Protocol-conforming third-party OCI agents are conditionally admitted only through an attested live gVisor `runsc` host and have no direct browser authority; mandatory tests pass, but this host has no registered live `runsc` lane. “Fully sensed” is bounded to declared healthy sensor families; total host observability, provider-quality comparison, and public comparative results remain unproven |
| Research/publication programme | Private source, opportunity, invention, and publication-readiness ledgers maintained; public novelty and submission remain human/external gates |
| Onboarding and adoption | Account-free `init`, local `doctor`, reviewed data removal, installation/first-value/air-gap guides, and user pathways implemented |
| Release and governance | Deterministic SBOM/checksum tools, twelve evidence-based stable gates, cross-platform acceptance CI, candidate-only keyless Sigstore signing, GitHub provenance attestation, public governance, and compatibility policy implemented. The workflow refuses to describe its artifact as stable 1.0; the first stable public release remains blocked on external receipts and founder approval |
| Standards and long horizon | Neutral conformance kit, schema/change governance, archival policy, and open-ended research branches implemented; independent adoption remains unproven |
| Remaining validation | Founder-authorized non-fixture targets, real Windows/macOS/Linux desktop-driver fixtures, a registered live gVisor host with independently built third-party agent images, credentialed multi-provider studies, independent causal reviewers and implementation owners, production community/monitor deployments, strongest-baseline benchmarks, external user workflows, and a promoted stable release |

The first engineering objective is now implemented as a bounded synthetic
no-Atlas/no-MELRA vertical slice:

```text
planted sleeper component
    → restricted synthetic environment
    → hidden-trigger search
    → deterministic canary/egress oracle
    → signed .sova-trace
    → offline verification
    → replay and repeated reproduction
    → honest technical report
```

## Open-source and commercial boundary

SOVA OSS is a standalone experimental local instrument for users to test and
understand systems they are authorized to assess. It is not a crippled edition
of a paid product:

- every defined SOVA OSS command and generic security workflow belongs in the public repository;
- no SOVA OSS feature depends on a TRUSCOR account, service, private plugin, or feature flag;
- SOVA OSS outputs are visibly labelled operator-controlled self-assessments;
- SOVA OSS never issues a TRUSCOR certificate, independent attestation, financial-loss conclusion, premium, or underwriting output;
- SOVA OSS never contains TRUSCOR’s private corpus, corpus-derived tuning, client-confidential findings, matched loss pairs, private honeypot intelligence, commercial risk models, or signature authority.

**SOVA Engine** is the name of TRUSCOR's separate proprietary system. The public runtime is called **SOVA OSS Core** or **SOVA Runtime**. A fork can reproduce and improve the public instrument; open source cannot honestly prevent that. A fork does not receive TRUSCOR's private intelligence, separately governed review process, protected identity, accumulated operating record, commercial relationships, or any authority TRUSCOR may independently establish.

The separation is:

> **SOVA OSS provides the instrument and first-party evidence. TRUSCOR combines private intelligence with separately governed operation and accountability.**

Read [the complete open/private decision](./docs/decisions/0003-open-source-and-proprietary-boundary.md), [the self-assessment decision](./docs/decisions/0004-self-assessment-and-truscor-boundary.md), [the Topic 00 constitution](./docs/decisions/0005-topic-00-project-constitution.md), and [the public repository policy](./docs/governance/public-repository-boundary.md).

## Licence, attribution, and citation

SOVA OSS is licensed under the [Apache License 2.0](./LICENSE). Developers, researchers, individuals, enterprises, and commercial users may use, modify, distribute, and build on the public repository subject to that licence.

When distributing SOVA OSS or a derivative work, preserve the licence, relevant copyright and attribution notices, the contents of [NOTICE](./NOTICE), and clear notices for modified files as required by Apache-2.0. The licence also includes an express patent grant from contributors and does not grant rights to use project trademarks.

Apache-2.0 does not require a private internal user or a service that never distributes the software to advertise TRUSCOR publicly. That restriction is deliberate: adding a field-of-use or mandatory-promotion condition would make the project less interoperable and could prevent it from meeting accepted open-source criteria. Distributed copies and forks do carry enforceable notice obligations.

For papers, reports, theses, benchmarks, and datasets, use the repository's [CITATION.cff](./CITATION.cff). GitHub exposes it through **Cite this repository**. Citation is a research-norm request in addition to the legal notice obligations for software distribution.

**SOVA-OSS™** is the canonical project mark. The software licence does not license the name or owl logo. Materially modified forks must use a distinct primary name and may describe themselves truthfully as “based on SOVA-OSS” or “a fork of SOVA-OSS.” See the complete [trademark and fork-naming policy](./TRADEMARKS.md).

## Contributing

The project is pre-alpha, but its contribution and safety rules are active now:

- read [CONTRIBUTING.md](./CONTRIBUTING.md) before proposing a change;
- set up the locked environment using the [development guide](./docs/engineering/development.md);
- follow the [testing strategy](./docs/engineering/testing.md) and [repository controls](./docs/governance/repository-controls.md);
- sign every commit using the [Developer Certificate of Origin](https://developercertificate.org/) (`git commit -s`);
- follow the [dual-use policy](./DUAL_USE_POLICY.md) for scenarios, fixtures, search methods, and registry content;
- report vulnerabilities privately under [SECURITY.md](./SECURITY.md);
- respect the [public repository boundary](./docs/governance/public-repository-boundary.md) and [trademark policy](./TRADEMARKS.md).

Contribution areas will include:

- target and framework adapters;
- deterministic oracles;
- sandbox backends;
- trace importers and exporters;
- safe vulnerable fixtures;
- `.sova` scenarios;
- provider integrations;
- replay and visualization;
- documentation and reproducibility.

Never open public issues containing live credentials, private traces, unpatched exploit payloads, or confidential target information.

## Connect

<table>
  <tr>
    <td><strong>SOVA / TRUSCOR</strong></td>
    <td><a href="https://truscor.org">truscor.org</a></td>
  </tr>
  <tr>
    <td><strong>Project lead</strong></td>
    <td><a href="mailto:gautam@truscor.org">gautam@truscor.org</a></td>
  </tr>
  <tr>
    <td><strong>XAGI Labs</strong></td>
    <td><a href="https://xagilabs.com">xagilabs.com</a></td>
  </tr>
  <tr>
    <td><strong>XAGI Labs on GitHub</strong></td>
    <td><a href="https://github.com/XAGI-Lab">github.com/XAGI-Lab</a></td>
  </tr>
  <tr>
    <td><strong>SOVA repository</strong></td>
    <td><a href="https://github.com/TRUSCOR/SOVA-OSS">TRUSCOR/SOVA-OSS</a></td>
  </tr>
</table>

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/truscor-mark-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="./assets/truscor-mark-light.svg">
    <img src="./assets/truscor-mark-light.svg" width="58" alt="TRUSCOR mark">
  </picture>
</p>

<p align="center">
  <img src="./assets/truscor-wordmark.png" width="430" alt="TRUSCOR wordmark">
</p>

<p align="center">
  <strong>See the agent. Find the condition. Preserve the evidence.</strong>
</p>

<p align="center">
  Built in the open by <a href="https://truscor.org">TRUSCOR</a>, with execution infrastructure from the wider <a href="https://xagilabs.com">XAGI Labs</a> ecosystem.
</p>

<p align="center">
  SOVA-OSS™ and the SOVA owl logo are trademarks of TRUSCOR. Apache-2.0 licenses the software, not the marks.
</p>
