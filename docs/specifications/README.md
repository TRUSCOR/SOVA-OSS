<!-- status: implemented -->

# Experimental SOVA format specifications

The current schemas are experimental `0.1.0` formats. They freeze safety,
identity, type-separation, canonicalization, and migration invariants without
claiming that the field set is ready for `1.0`.

- [`.sova` behavior capsule](./sova-capsule-0.1.md)
- [`.sova-trace` event stream](./sova-trace-0.1.md)
- [migration and compatibility](./migration-and-compatibility.md)
- [interoperability and fidelity](./interoperability.md)
- [privacy and selective disclosure](./privacy-and-disclosure.md)
- [format threat model](./threat-model.md)
- [executor capability contract](./executor-contract-0.1.md)
- [observable oracles and declared-outcome comparison](./observable-oracles-0.1.md)
- [comparability envelope and calibration report](./comparability-envelope-0.1.md)
- [authorization and safety contract](./authorization-safety-0.1.md)
- [containment backend admission](./containment-backends-0.1.md)
- [controller/worker production isolation](./controller-worker-production-isolation-0.1.md)
- [VM-hosted OCI isolation backend](./docker-desktop-oci-isolation-0.1.md)
- [synthetic detonation world](./synthetic-detonation-0.1.md)
- [MELRA executor adapter boundary](./melra-adapter-boundary-0.1.md)
- [capability map and reach model](./capability-map-0.1.md)
- [runtime orchestration and evidence firewall](./runtime-orchestration-0.1.md)
- [`sova check` and `sova demo`](./check-and-demo-0.1.md)
- [replay and semantic reproduction](./replay-and-reproduction-0.1.md)
- [evidence replay application](./evidence-replay-application-0.1.md)
- [capability-routed external execution](./external-execution-broker-0.1.md)
- [bounded trigger search](./trigger-search-0.1.md)
- [forensics and counterfactual attribution](./forensics-0.1.md)
- [blinded causal validation](./blinded-causal-validation-0.1.md)
- [evidence, adjudication, disclosure, and reports](./evidence-adjudication-disclosure-0.1.md)
- [offline evidence case workspace](./case-workspace-0.1.md)
- [composition and emergent-chain testing](./composition-testing-0.1.md)
- [safe real-task rehearsal](./rehearsal-0.1.md)
- [behavioral monitoring, CI, and self-check](./behavioral-monitoring-and-ci-0.1.md)
- [durable continuous monitoring service](./continuous-monitor-service-0.1.md)
- [registry, synchronization, adapters, and contributions](./registry-and-contributions-0.1.md)
- [loopback self-hosted community service](./self-hosted-community-service-0.1.md)
- [local MCP and human authorization](./local-mcp-0.1.md)
- [extensions, providers, targets, and interoperability](./extensions-providers-interoperability-0.1.md)
- [probe, local Arena, leaderboard, CTF, and replay media](./community-surfaces-0.1.md)
- [authorization-gated live browser assessment](./live-browser-assessment-0.1.md)
- [opaque persistent browser sessions](./persistent-browser-sessions-0.1.md)
- [authorized local-software assessment](./live-software-assessment-0.1.md)
- [bounded live browser campaign](./live-browser-campaign-0.1.md)
- [provider-assisted browser campaign](./provider-agent-browser-campaign-0.1.md)
- [autonomous policy-confined semantic browser workflow](./semantic-browser-workflow-0.1.md)
- [provider-capable local Agent Arena](./agent-arena-0.1.md)
- [real-time multi-agent Arena chamber](./arena-chamber-0.1.md)
- [executor-backed authorized browser swarm](./executor-backed-browser-swarm-0.1.md)
- [authorized target assessment](./authorized-target-assessment-0.1.md)
- [universal target intake](./universal-target-intake-0.1.md)
- [methodology compiler and native playbook library](./methodology-compiler-and-playbook-library-0.1.md)
- [security-tool adapters and evidence normalization](./security-tool-adapters-and-normalization-0.1.md)
- [neutral conformance kit](./conformance-kit-0.1.md)
- [supply-chain release artifacts](./supply-chain-release-0.1.md)
- [final-mile acceptance and stable-release gates](./final-mile-acceptance-0.1.md)
- [browser adapters and held-out website matrix](./browser-adapters-and-web-matrix-0.1.md)
- [contained consequential-action lab](./consequential-action-lab-0.1.md)
- [cross-platform accessibility-first desktop execution](./cross-platform-desktop-execution-0.1.md)
- [gVisor runsc isolation backend](./gvisor-runsc-isolation-0.1.md)
- [Sandboxed OCI agent runtime](./oci-agent-runtime-0.1.md)
- [claim-conditioned sensor coverage ledger](./sensor-coverage-ledger-0.1.md)
- [cross-provider and cross-model experiment matrix](./provider-experiment-matrix-0.1.md)
- [matched comparative benchmark protocol](./comparative-benchmark-protocol-0.1.md)
- [managed services and hosting boundary](./managed-services-and-hosting-0.1.md)
- [blinded validation, Registry beta, and launch gates](./blinded-validation-registry-and-launch-0.1.md)

The implementation and bounded validation result for the final three surfaces
is recorded in [Topics 21-23 validation](../engineering/topics-21-23-validation.md).
The onboarding, release, governance, conformance, and authorized-target fixture
work is recorded in [Topics 24-27 validation](../engineering/topics-24-27-validation.md).

The normative JSON Schema 2020-12 files ship in
[`src/sova/schemas`](../../src/sova/schemas/README.md). Python is the reference
implementation, not the specification. A conforming independent implementation
may use any language and must produce the same canonical bytes and validation
outcomes for the conformance corpus.

The schemas are immutable once included in a tagged release. Breaking
experimental changes receive a new schema version and an explicit migrator.
