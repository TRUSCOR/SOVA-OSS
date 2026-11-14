<!-- status: planned -->

# SOVA OSS — the launch checklist

**Opened:** 2026-09-08
**This is the list.** Everything between the code as it stands today and SOVA OSS
being publicly launched. Twelve phases, numbered in the order we do them.

Tick a box only when the evidence in its row exists. Not "it works" — the actual
receipt, digest, URL, or signature named in the row.

---

## How to read this

| Owner | Meaning |
|---|---|
| **ME** | I do it now. No dependency. |
| **YOU** | Only you can — money, credentials, a decision, a signature, an authorization. |
| **OTHER** | A third party — a reviewer, counsel, a volunteer. |
| **WAITING** | I do it, but a YOU or OTHER row above has to land first. |

**Phase 0 comes first and changes what the rest is aiming at.**
**Phases 1-6 are my build work and run in sequence after it.**
**Phases 7, 8 and 9 are yours and other people's — start them NOW, today, because
they run in parallel with everything I build and they are the long poles.**
Phases 10-12 close the release. **Phase 13 is mostly prepared before Phase 12 fires,
not after** — a launch improvised on the day is a launch wasted.

### Progress

| Phase | | Owner mix | Done |
|---|---|---|---|
| 0 | **Make it land** | ME + YOU | ☐ 0/18 |
| 1 | Make it installable | ME + YOU | ☐ 0/9 |
| 2 | Declare what is stable | YOU decides, ME writes | ☐ 0/8 |
| 3 | Finish the toolkit | ME | ☐ 0/9 |
| 4 | Open the contributor path | ME | ☐ 0/5 |
| 5 | Prove the format stands alone | ME + OTHER | ☐ 0/4 |
| 6 | Make contributions safe to accept | ME + YOU | ☐ 0/8 |
| 7 | Prove the isolation | YOU + OTHER | ☐ 0/9 |
| 8 | Deploy the Registry | YOU + OTHER | ☐ 0/7 |
| 9 | Get independently reviewed | YOU + OTHER | ☐ 0/5 |
| 10 | Reconcile every public claim | YOU + ME | ☐ 0/8 |
| 11 | Final release evidence | WAITING | ☐ 0/5 |
| 12 | Launch | YOU | ☐ 0/8 |
| 13 | **Landing and aftermath** | YOU + ME | ☐ 0/10 |
| | **Total** | | **0 / 113** |

### Where the code stands today

Verified 2026-09-08 on a clean run: **2,649 tests pass, 29 capability-gated skips,
zero failures**, 95.11% combined coverage, 149/149 CLI paths, Ruff and strict mypy
clean, repository policy and public-boundary scans pass. The engineering is
essentially done — this list is almost entirely evidence, distribution, and people.

---

## Phase 0 — Make it land

*Everything here changes what "installable" is even supposed to look like, so it comes
first. This phase is not polish. A great instrument nobody can find, start, or
understand in sixty seconds is a failed project, and that is the most common way
excellent open source dies.*

**The psychology this phase serves.** People adopt a tool that respects their time,
makes them feel competent, gives them something to show, and does not lie to them. Every
row below buys one of those four.

- [ ] **0.1** Rename the repository to `sova` — **YOU** — `S.O.V.A---OSS---TRUSCOR` is unsearchable, untypeable and unsayable
- [ ] **0.2** Sweep every reference the rename breaks — **ME** — 23 references across 13 files including `src/sova/evidence/bundle.py`, `src/sova/adapters/security_catalog.py`, two test files, `NOTICE`, `CITATION.cff`, `pyproject.toml`, `README.md`, `CHANGELOG.md`, the community `Dockerfile` and `installation.md`; touches source, so the full gate must rerun
- [ ] **0.3** Lazy-load the CLI to reach sub-200 ms cold start — **ME** — measured `sova --version` under 200 ms, down from 1,296 ms; `sova/cli.py` currently imports `acceptance`, `community`, `detonation` and `formats` purely to build the argparse tree
- [ ] **0.4** Add a real UX target to the perf budget beside the regression ceiling — **ME** — the current budget measures "does not get worse", never "feels instant"
- [ ] **0.5** Zero-config `sova check` that finds MCP servers already installed on the user's machine — **ME** — reads Claude Desktop and Cursor config; no target file, no manifest, no flags. This is the wedge
- [ ] **0.6** Design the empty result so a clean machine still feels valuable — **ME** — "found nothing" must show what was checked, what could not be checked, and why; a blank pass is the worst possible first run
- [ ] **0.7** Surface the local-first guarantee at first run — **ME** — nothing left your machine, no account, no telemetry, stated plainly where a new user sees it before they worry about it
- [ ] **0.8** `npx sova` shim bootstrapping a managed Python via `uvx` — **ME** — MCP's native language is TypeScript, the TS SDK has passed 150M downloads and every major client is Node
- [ ] **0.9** Shareable replay clip with a verify link — **ME** — short, captioned, opens at the decisive moment. The mechanism is ~80% built and unpackaged. This is the status object people post
- [ ] **0.10** Record *the* demo — **ME + YOU** — the 60-second video at the top of the README. An asset, not a feature, and currently nobody owns it
- [ ] **0.11** Rewrite the README around the demo — **ME** — opens with the clip and one command; the pre-alpha honesty moves below the fold where it builds trust instead of repelling
- [ ] **0.12** One front door, not 149 — **ME** — the README teaches a single command; the other 148 stay fully supported and discoverable behind it
- [ ] **0.13** Publish a cross-platform capability matrix — **ME** — what works on Windows, macOS and Linux. The native computer adapter is Windows-only and P-54 says cross-platform is unproven. A Mac user who installs cleanly and then hits dead commands is a worse outcome than one who never installed
- [ ] **0.14** Make the honesty an asset, not a disclaimer — **ME** — "the tool that tells you what it could not determine" is rare and trusted in a field of overclaimers. Position `unknown` / `inconclusive` / `unsupported` as a feature on the front page
- [ ] **0.15** Publish the `.sova` specification standalone, at its own URL, with the conformance kit beside it — **ME** — a format that lives only inside one program is a file layout, not a standard
- [ ] **0.16** Reposition the Registry as **the Atlas of Reproducible Agent Vulnerabilities** — **ME** — ARVO exists for traditional software and is cited; there is no agent equivalent. Same machinery, a name that fills a gap the literature already named
- [ ] **0.17** Decide how the README mentions SOVA Engine — **YOU** — ADR-0003 forbids the OSS being "a trial or upsell funnel". Whether and how the commercial product appears on the public front page is a trust decision
- [ ] **0.18** Join the NIST CAISI AI Agent Standards Initiative, CSA agentic working group and OWASP Agentic Top 10 — **YOU** — nearly free, and the difference between a popular repo and the reference implementation. v4.7 called for this on month one and it never happened

---

## Phase 1 — Make it installable

*Nobody can use SOVA today. There is no install path. Nothing else on this list
matters until this is true.*

- [x] **1.1** Confirm the `sova-oss` name is free on PyPI — **ME** — lookup recorded *(2026-11-15: `sova-oss` 404 before release; `sova` is an unrelated SLAM package)*
- [x] **1.2** Create the PyPI project, enable Trusted Publishing (OIDC) for this repo — **YOU** — publisher configured, no long-lived token anywhere *(2026-11-15: pending publisher TRUSCOR/SOVA-OSS, publish.yml, environment pypi; project created by the first upload)*
- [x] **1.3** Add a tag-gated publish workflow with manual approval — **ME** — workflow refuses to run without explicit dispatch *(`.github/workflows/publish.yml`: workflow_dispatch only, tag must equal the package version)*
- [ ] **1.4** Dry-run publish to TestPyPI — **WAITING** — TestPyPI artifact URL *(build half passed in run 43637977146; no TestPyPI publisher was configured, so 0.1.0 went to PyPI directly)*
- [x] **1.5** Clean-environment install on Windows — **ME** — `sova --version` + `sova doctor` output *(2026-11-15: `pip install sova-oss` from PyPI into a fresh CPython 3.12 venv, `sova 0.1.0`, `sova doctor` status pass, `sova verify` on a released finding: verified)*
- [ ] **1.6** Clean-environment install on Linux (WSL Ubuntu) — **ME** — same, on Linux *(partial: publish.yml installed the built wheel in a clean Ubuntu venv and ran `sova --version`, run 43640273688; `sova doctor` on Linux not yet recorded)*
- [ ] **1.7** Clean-environment install on macOS — **OTHER** — same, from a Mac we don't have
- [x] **1.8** `docs/guides/installation.md` matches observed behavior exactly — **ME** — doc diff *(release commit 2484528)*
- [x] **1.9** README install block matches — **ME** — doc diff *(release commit 2484528)*

---

## Phase 2 — Declare what is stable

*People cannot build on a surface whose stability is undeclared. Done in 0.1.0: see
`docs/governance/api-stability.md`.*

- [x] **2.1** Decide the frozen surface — **YOU** — recommended: freeze `.sova`, `.sova-trace`, the 61 schemas and the CLI leaves; leave the Python API experimental *(founder, 2026-11-15: release the format with the paper. Frozen: `.sova`, `.sova-trace` and `sova.calibration` 0.1.0; stable within 0.1.x: the nine core CLI leaves; the other schemas, leaves and the Python API stay experimental)*
- [x] **2.2** Write `docs/governance/api-stability.md` — **WAITING** — doc exists, linked from README *(release commit 2484528)*
- [x] **2.3** Enumerate the frozen surface explicitly — **WAITING** — an actual list, not a description *(release commit 2484528)*
- [x] **2.4** Enumerate the experimental surface explicitly — **WAITING** — actual list *(release commit 2484528)*
- [x] **2.5** Deprecation policy and notice period, consistent with ADR-0002 — **WAITING** — doc section *(release commit 2484528)*
- [x] **2.6** Align `pyproject.toml` version + Development Status with the statement — **WAITING** — metadata stops contradicting the contract *(0.1.0, Development Status 4 - Beta; release commit 2484528)*
- [x] **2.7** Extend `test_cli_surface_audit.py` so a frozen CLI leaf cannot vanish silently — **WAITING** — test fails when a frozen leaf is removed *(`test_stable_cli_leaves_stay_registered` in tests/unit/test_front_door.py; release commit 2484528)*
- [x] **2.8** Update the README status block — **WAITING** — doc diff *(release commit 2484528)*

---

## Phase 3 — Finish the toolkit

*Admitted tools can only be executed from Python today. A contributor cannot run ZAP
or Nuclei from the CLI. That is the "one tool" gap.*

- [ ] **3.1** Design the `sova adapter run` argument surface — **ME** — design note in the adapter spec
- [ ] **3.2** Route execution through the authority kernel — **ME** — refusal test with no live authorization
- [ ] **3.3** Bind containment selection — **ME** — backend recorded in the trace
- [ ] **3.4** Gate external data transfer behind the disclosure gate — **ME** — denied-by-default test
- [ ] **3.5** Emit a signed trace for the run — **ME** — trace verifies offline
- [ ] **3.6** Normalize output to observations, never auto-findings — **ME** — `findingConfirmed: false` assertion
- [ ] **3.7** Adverse matrix: timeout, partial output, corrupt output, version drift, cleanup — **ME** — one test per class
- [ ] **3.8** CLI parser-to-handler audit stays at 100% — **ME** — `audit_cli_coverage.py` pass
- [ ] **3.9** Update the command reference and adapter specification — **ME** — doc diff

---

## Phase 4 — Open the contributor path

*This is the ecosystem. One example extension is not a contributor path.*

- [ ] **4.1** Write `docs/guides/building-on-sova.md` — **ME** — covers all 8 plug points and the executor contract
- [ ] **4.2** Add a second reference extension at a different plug point — **ME** — runs through `sova extension run`
- [ ] **4.3** Add a copyable extension starter template — **ME** — skeleton under `examples/extensions/`
- [ ] **4.4** Full round trip: author a playbook → keygen → sign → stage → review → resolve — **ME** — every step recorded
- [ ] **4.5** Link the guide from `CONTRIBUTING.md` and the README — **ME** — doc diff

---

## Phase 5 — Prove the format stands alone

*The only real proof `.sova` is a substrate and not one program's file layout. Costs
one competent stranger about a day.*

- [ ] **5.1** Export the conformance kit, verify its self-check — **ME** — kit digest
- [ ] **5.2** Write the implementer brief: what to build, run, and report — **ME** — brief exists
- [ ] **5.3** Find a volunteer implementer — **YOU** — named person
- [ ] **5.4** Record the result including every vector that failed — **OTHER** — report kept verbatim, failures retained

---

## Phase 6 — Make contributions safe to accept

*The registry will receive working offensive AI-security modules. It cannot open
without a named human responder and a rehearsed process.*

- [ ] **6.1** Write `docs/governance/community-module-triage.md` — **ME** — doc exists
- [ ] **6.2** Intake screening checklist — **ME** — doc section
- [ ] **6.3** Dual-use review criteria bound to `DUAL_USE_POLICY.md` — **ME** — doc section
- [ ] **6.4** Fix the contribution secret-scan gap — **ME** — JSON-escaped secrets currently evade `_SECRET` in `registry/contribution.py`; regression test proving `{"payload": "{\"token\": \"…\"}"}` is caught
- [ ] **6.5** Locate and test the no-unpatched-payload enforcement point — **ME** — test
- [ ] **6.6** Name the responder and the response target — **YOU** — named person, stated hours
- [ ] **6.7** Takedown procedure — **ME** — doc section
- [ ] **6.8** Rehearse the whole process once against a synthetic submission — **ME** — recorded rehearsal

---

## Phase 7 — Prove the isolation  ⚡ START NOW

*Everything below row 7.2 is already written, tested and waiting for hardware. One
host unlocks three gates. This runs in parallel with Phases 1-6.*

- [ ] **7.1** Provide a dedicated patched Linux/KVM host, or authority to provision one — **YOU** — reachable as `ssh sova-worker`; the private key never enters chat or Git
- [ ] **7.2** Configure the SSH alias locally — **YOU** — `ssh -G sova-worker` resolves a real host
- [ ] **7.3** Run the read-only host preflight — **WAITING** — green host-preflight receipt
- [ ] **7.4** Fill the worker policy with exact observed paths and SHA-256 pins — **WAITING** — no `REPLACE_WITH_*` placeholder remains
- [ ] **7.5** Provision with `--apply --ack-dedicated-host` — **WAITING** — explicit mutation authorization recorded first
- [ ] **7.6** Execute one live Firecracker microVM through the exact jailer lifecycle — **WAITING** — execution receipt
- [ ] **7.7** Run the positive control plus all ten malicious-guest classes — **WAITING** — eleven case receipts binding execution, network, raw evidence, cleanup
- [ ] **7.8** Compile the exact-host receipt from real observed cases only — **WAITING** — exact-host acceptance receipt
- [ ] **7.9** Independent isolation review of the exact measured configuration — **OTHER** — signed receipt; reviewer must not overlap any internal role

Negative results and incomplete cleanup are recorded as failures. No
escape-impossibility claim is ever made.

---

## Phase 8 — Deploy the Registry  ⚡ START NOW

*Built and loopback-proven, never deployed. For a community platform the module hub
is the product. Longest build-side pole: 3-6 weeks of real ops.*

- [ ] **8.1** Provide cloud account, domain and TLS — **YOU** — infrastructure exists
- [ ] **8.2** Name the operations owner and incident responder — **YOU** — named person
- [ ] **8.3** Run the immutable-image preflight — **WAITING** — preflight pass
- [ ] **8.4** Deploy the hardened blueprint — **WAITING** — service reachable
- [ ] **8.5** Exercise all ten readiness controls — **WAITING** — identity, moderation, malware/secret screening, rate+DDoS, encrypted backup, restore, rollback, monitoring, key rotation, incident response; one operational receipt each
- [ ] **8.6** Restore drill from a real backup — **WAITING** — restored service verified
- [ ] **8.7** Independent security review of the live public service — **OTHER** — signed review

---

## Phase 9 — Get independently reviewed  ⚡ START NOW

*All five must be role-separated; the verifier rejects shared keys and internal
overlap. **I am structurally ineligible for every row here.** Longest pole overall —
ask people today.*

- [ ] **9.1** Founder acceptance — **YOU** — signed role-scoped receipt
- [ ] **9.2** Independent technical validation — **OTHER** — signed receipt, no internal overlap
- [ ] **9.3** Independent isolation review — **OTHER** — must be a different person from 9.2
- [ ] **9.4** Legal / licence / public-disclosure review — **OTHER** — qualified counsel; none assigned yet
- [ ] **9.5** Security sign-off — **OTHER** — signed receipt

---

## Phase 10 — Reconcile every public claim

*The replacement copy is already written and waiting in the reconciliation packet.
truscor.org currently claims autonomous enterprise testing and actuarial risk
ratings that this codebase does not support.*

- [ ] **10.1** Approve the exact replacement copy for all seven surfaces — **YOU** — recorded approval
- [ ] **10.2** Deploy the approved wording to truscor.org — **YOU** — served response captured, not a search snippet
- [ ] **10.3** Check the GitHub repo description and social preview for retired claim language — **ME** — current text recorded
- [ ] **10.4** Freeze README, docs, demo, Registry and release-note bytes for the release commit — **WAITING** — digests
- [ ] **10.5** Bind the cleared paper, or an explicit no-paper release notice — **YOU** — decision recorded
- [ ] **10.6** Revise the README heading "The headline capability: find the sleeper" — **ME** — sleeper search is a shipped mechanism, not the OSS headline claim; the body text below it is already correctly hedged and stays
- [ ] **10.7** Add a claims-register row governing the OSS↔Engine capability boundary — **ME** — controls the exact wording of "OSS ships the mechanism, Engine has the tuned quality, OSS makes no parity claim"; no register row covers this today
- [ ] **10.8** `sova release dossier` reports `publicClaimsReconciled=true` — **WAITING** — dossier output

---

## Phase 11 — Final release evidence

*Runs last, on the exact release commit, after everything above is green. Any source
or public-copy change invalidates it and forces a recompute.*

- [ ] **11.1** Select the exact release commit — **YOU** — commit SHA
- [ ] **11.2** Full tests, static checks, dependency/licence/secret audits from a clean checkout — **WAITING** — signed deterministic-release-checks receipt
- [ ] **11.3** Deterministic build, isolated-wheel smoke, SBOMs, checksums — **WAITING** — byte-identical rebuild
- [ ] **11.4** Hosted CI provenance attestation — **WAITING** — attestation URL
- [ ] **11.5** Recompute the candidate and dossier with an out-of-band trust-policy pin — **WAITING** — dossier reports zero hold reasons

---

## Phase 12 — Launch

*Every row is a separate action needing its own explicit authorization from you, on
the day. Nothing here ever happens automatically.*

- [ ] **12.1** Push the branch — **YOU**
- [ ] **12.2** Tag the release — **YOU**
- [ ] **12.3** Create the GitHub release — **YOU**
- [ ] **12.4** Publish the package — **YOU**
- [ ] **12.5** Deploy the Registry publicly — **YOU**
- [ ] **12.6** Change the website — **YOU**
- [ ] **12.7** Announce — **YOU**
- [ ] **12.8** Independently re-verify the published artifacts after release — **ME**

---

## Phase 13 — Landing and aftermath

*Phase 12 makes SOVA public. This phase decides whether anyone notices, and whether the
project survives it going well. Most of the rows below must be **prepared before** the
Phase 12 actions fire — a launch you improvise on the day is a launch you waste.*

### Before the announcement

- [ ] **13.1** Define what success means, with numbers — **YOU + ME** — telemetry is off by design, so measurement is external: stars, PyPI downloads, forks, issues opened, Atlas entries, clips shared. Pick 30-day and 90-day targets. Without a target you cannot tell a good launch from a bad one, and you cannot iterate on the wedge if it misses
- [ ] **13.2** Write the launch content per channel — **ME + YOU** — Show HN, r/netsec, r/LocalLLaMA, the MCP community and the agentic-security working groups each need different framing. Same truth, different entry point
- [ ] **13.3** Sequence the launch across days, not one blast — **YOU** — decide order, timing and who posts. A single simultaneous push wastes the follow-up audience
- [ ] **13.4** Prepare answers to the five hardest questions — **ME** — "how is this different from Promptfoo/garak", "why should I trust your evidence", "what does it actually find", "is this just a funnel for your paid product", "why is it pre-alpha". Being ready is the difference between a good thread and a bad one
- [ ] **13.5** Name a support owner and a response target — **YOU** — Phase 6.6 names a *safety* responder; nobody owns ordinary issues. Week one of a landing launch produces real volume
- [ ] **13.6** Set week-one triage capacity — **YOU + ME** — what gets answered, what gets labelled, what waits. An unanswered first issue is a permanent signal about the project

### After the announcement

- [ ] **13.7** Answer every first-week issue and discussion — **YOU + ME** — early responsiveness compounds; early silence is fatal and cannot be recovered later
- [ ] **13.8** Publish a follow-up showing what real users found — **ME + YOU** — the second wave of attention comes from evidence the tool worked for someone who is not us
- [ ] **13.9** Review at 30 days against 13.1 — **YOU + ME** — if the wedge missed, say so plainly and change it rather than repeating the launch
- [ ] **13.10** Feed what was learned back into the wedge and the README — **ME** — the first hundred users will show which sentence they did not understand

**Phase 13 exit gate:** the 30-day review is written down and honest, whether or not it
is good news. A launch that is never measured cannot be repeated or corrected.

---

## What SOVA OSS claims, and what it does not

**SOVA OSS ships the complete mechanism.** Recon, mapping, exploration,
methodology, adapters, oracles, evidence, reproduction, replay — and
conditional-trigger ("sleeper") search. It genuinely attempts all of it, sleeper
discovery included. Every one of those paths is open, auditable and extensible.
Nothing is stubbed out or held back.

**What it does not claim is quality.** Being *excellent* at sleeper discovery is
the product of accumulated tuning and learned intelligence, and under
[ADR-0003](../decisions/0003-open-source-and-proprietary-boundary.md) that stays
with the proprietary SOVA Engine. So the OSS claims exactly this and no more:

- it implements the mechanism, end to end, in the open;
- it is the foundation others fork and specialize into very good testers;
- it makes **no parity claim** with SOVA Engine, and no claim to find 99% or 100%
  of what a tuned tester would find.

**The constraint that keeps this honest.** ADR-0003 requires the public project to
be *non-crippled* and forbids hiding an essential implementation behind an account,
feature flag, proprietary plugin or network call. The Engine's advantage must
therefore be learned intelligence and accumulated work applied *on top of* the open
mechanism — never a mechanism removed from the OSS to widen the gap. Stripping
capability out of the public tree to flatter the closed product would violate the
constitution and forfeit exactly the contributor trust the ecosystem runs on.

**Therefore not on this list:** the blinded multi-provider study, matched
scanner/agent baselines, and the eight-class field-target run. Those measure
detection *performance*, which is an Engine and research claim. They remain
mandatory before any comparative, superiority, coverage or field-performance
statement — including any statement that SOVA finds what other tools miss — but
they do not block this release. Recorded formally in the
[controlling gate ledger](./universal-security-launch-checklist-2026-08-26.md),
which remains the machine-readable ledger that receipts and the release dossier
cite. This file is the plan; that file is the ledger.

---

## Changelog

| Date | Change |
|---|---|
| 2026-09-08 | Opened. Clean green baseline established (2,649 pass / 0 fail). Registry backup `MemoryError` fixed, commit `6f9418d`. Launch rescoped to the infrastructure release, commit `f5085c5`. |
