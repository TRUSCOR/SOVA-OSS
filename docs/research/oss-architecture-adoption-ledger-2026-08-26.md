<!-- status: research -->

# Open-source security architecture adoption ledger — 2026-08-26

This is the refreshed P0 research decision record for the universal-security
roadmap. It answers a narrow engineering question: what should SOVA adapt, invoke,
benchmark against, or reject? It is not a claim that every listed project was
security-audited or that repository popularity proves quality.

No third-party source, payload corpus, playbook prose, template, or dataset was copied
in P0. Before a later file-level adaptation, record the exact upstream commit/file,
licence and notice obligations, modifications, tests, and provenance in the change
that introduces it.

## Decision scale

| Decision | Meaning |
|---|---|
| **ADAPT** | Narrow architecture/file candidate; file-level audit required before code enters SOVA |
| **ADAPTER** | Run as a pinned external tool through SOVA's executor/evidence contracts |
| **BENCHMARK** | Import/translate licensed tasks and scorers with upstream identity preserved |
| **REFERENCE** | Use concepts, taxonomy, or methodology; do not copy code/content |
| **HOLD/REJECT** | Licence, maturity, monolith, duplication, safety, or evidence boundary is unacceptable now |

## Core architectural conclusion

No reviewed repository is a drop-in universal pentest engine. The common useful
pattern is staged discovery, specialized roles, a task/workflow graph, bounded tool
execution, resumable state, and structured reporting. The common missing pieces are
target-bound authority, trustworthy effect receipts, independent oracle calibration,
fresh reproduction, portable signed evidence, replay, explicit incomplete coverage,
and production hostile-agent isolation. SOVA therefore keeps its current core and
imports capabilities through adapters.

## P3 implementation refresh — 2026-08-27

The release, licence, output, privacy, update, and failure seams for the selected
P3 tools were rechecked against primary upstream sources. Exact pins, rejected
shortcuts, the Trivy 2026 supply-chain control, the Nmap/Npcap legal hold, and
the implemented validation boundary are recorded in
[the P3 security-adapter research refresh](./p3-security-adapter-research-2026-08-27.md).

The resulting implementation does not vendor upstream tool code or content. It
adds 12 promoted descriptors and parsers; constrained ffuf, httpx, testssl.sh,
sqlmap, mitmproxy, zgrab2, generic MCP stdio, and generic HTTP descriptors; and
an enforced Nmap legal hold. Every runtime executable remains operator-supplied
and SHA-256 bound. The SOVA authority kernel, executor contract, trace, parser,
and later oracle/reproduction stages remain the controlling architecture.

## AgentDojo optional runtime dependency — 2026-11-14

`sova rerun` and `sova matrix` run recorded AgentDojo findings again on a chosen
model. They use AgentDojo itself, not a re-implementation, so that a fresh run
uses the same suites, injection vectors, attack templates, pipeline settings, and
security and utility checks as the run that was recorded.

| Project | Decision | Boundary |
|---|---|---|
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) 0.1.35 | **OPTIONAL RUNTIME DEPENDENCY** (`sova-oss[agentdojo]`, exact pin `agentdojo==0.1.35`) | MIT licence; installed by the user, not vendored. Imported lazily only when a run starts; inspecting or verifying a capsule never imports it. The runner refuses any other installed version because it relies on 0.1.35's pipeline configuration and message-conversion helpers. Only AgentDojo's simulated environments are run; every model call goes through SOVA's own paced, retried, recorded provider clients, and keys come only from named environment variables. AgentDojo's security verdict is recorded as the benchmark's oracle and used as the default judge, not as proof that an attack happened: its checks can score a warning that names the attacker's target as an attack. The 0.1.35 JSON tool-output option cannot serialize dates; SOVA substitutes an ISO-8601 date writer and keeps the spotlighting delimiters. |

The OpenAI and Anthropic Python SDKs (Apache-2.0) arrive with the extra as
AgentDojo dependencies and are imported only to build those provider clients.

## Autonomous pentest and cyber-agent frameworks

| Project | Decision | What is useful | Why not wholesale copy |
|---|---|---|---|
| [AutoPentest AI](https://github.com/bhavsec/autopentest-ai) | **ADAPT** after file audit | Apache-2.0 Python modules for hierarchical task trees, endpoint priority, knowledge graph, output parsing/verification, context compression, and phase gates | Claude-driven workflow, bundled third-party guidance, Docker tool image, and its truth model do not replace SOVA authority/evidence; bundled prose needs separate rights review |
| [PentAGI](https://github.com/vxcontrol/pentagi) | **REFERENCE** | Flow/task/subtask/action hierarchy, specialist agents, memory and multi-provider orchestration | Go/TypeScript microservice stack is heavy and duplicative; product evidence/isolation claims are not SOVA contracts |
| [PentestGPT](https://github.com/GreyDGL/PentestGPT) | **BENCHMARK/REFERENCE** | Staged autonomous pipeline and published/XBOW-style evaluation route | Do not inherit telemetry/default integrations or a second state/runtime model |
| [PentestAgent](https://github.com/GH05TCREW/pentestagent) | **REFERENCE**, licence hold | Playbook organization, modular tools/MCP, self-spawn concepts | Exact current licence and all playbook provenance must be resolved; SOVA already owns orchestration/runtime |
| [CAI](https://github.com/aliasrobotics/cai) | **REFERENCE/HOLD** | Agents, tools, handoffs, patterns, turns, tracing, HITL architecture | Current commercial-use language is incompatible with assuming ordinary open-source reuse; no code adaptation without qualified licence review |
| [Akira](https://github.com/kalpmodi/akira) | **REFERENCE** | Hypothesis/state bus and technique-manifest concepts | Technique decisions and signals must map into SOVA target generations and traces, not form a parallel evidence model |
| [HexStrike AI](https://github.com/0x4m4/hexstrike-ai) | **REFERENCE/ADAPTER CATALOG** | Broad security-tool catalog and orchestration examples | Large monolithic server and very broad tool surface create audit and least-privilege problems |
| [pentest-mcp](https://github.com/openbashok/pentest-mcp) | **REFERENCE** | Small FastMCP wrappers demonstrate common scanner I/O | Thin wrappers do not supply authorization, containment, parser assurance, or vulnerability truth |
| [JuliusHenke/autopentest](https://github.com/JuliusHenke/autopentest) | **REJECT CORE** | Research baseline | Experimental breadth/performance is insufficient for a production architecture |

**Selected adaptation order:** first study AutoPentest's task tree, endpoint priority,
parser verification, and context compression as separate files. Reimplement only the
parts that survive compatibility, security, licence, and test review. PentAGI and CAI
inform orchestration comparisons; they do not become dependencies.

## Web, API, protocol, and network tools

| Project | Decision | SOVA integration boundary |
|---|---|---|
| [OWASP ZAP](https://github.com/zaproxy/zaproxy) | **ADAPTER** | Generate a pinned Automation Framework plan; ingest JSON/XML reports and raw receipts; SOVA owns target scope, authentication references, authority, and confirmation |
| [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates) / [Nuclei](https://github.com/projectdiscovery/nuclei) | **ADAPTER** | Pin engine plus template commit/digest; template match is an observation until reproduced by a SOVA oracle |
| [Schemathesis](https://github.com/schemathesis/schemathesis) | **ADAPTER** and possible library integration | Reuse its OpenAPI/GraphQL examples, coverage, fuzzing, and stateful phases; normalize requests/responses/events; do not duplicate its generator |
| [ffuf](https://github.com/ffuf/ffuf) | **ADAPTER** | Bounded content/vhost/parameter discovery with exact wordlist provenance and rate budgets |
| [httpx](https://github.com/projectdiscovery/httpx) | **ADAPTER** | Passive/active service observations under explicit destination policy |
| [testssl.sh](https://github.com/testssl/testssl.sh) | **ADAPTER** | TLS configuration observations with executable/version and target fingerprint |
| [sqlmap](https://github.com/sqlmapproject/sqlmap) | **ADAPTER after licence/safety review** | Consequential techniques require destructive-level approval, containment, and exact cleanup/evidence rules |
| [mitmproxy](https://github.com/mitmproxy/mitmproxy) | **ADAPTER** | Operator-authorized traffic capture/transform; certificate and captured data remain secret-scoped and non-public by default |
| [Nmap](https://github.com/nmap/nmap) | **HOLD** for specific shipped adapter | NPSL broadly addresses software designed to execute/parse Nmap; keep user-installed/generic until qualified review clears distribution/integration |
| [OWASP API Security Testing Framework](https://github.com/OWASP/www-project-api-security-testing-framework) | **REFERENCE** | Map its API tests into native playbooks only after maturity and CC/licence separation review |

## AI, model, agent, MCP, and A2A security

| Project/standard | Decision | SOVA integration boundary |
|---|---|---|
| [PyRIT](https://github.com/microsoft/pyrit) | **ADAPTER** | Targets, converters, scorers, and orchestrators run as a pinned test generator; SOVA calibrates/promotes oracles and packages evidence |
| [garak](https://github.com/NVIDIA/garak) | **ADAPTER** | Preserve generator/probe/detector/harness/evaluator identity and raw output; detector result is not automatically a finding |
| [promptfoo](https://github.com/promptfoo/promptfoo) | **ADAPTER** | Use target/plugin/strategy configuration with remote generation and sharing disabled by default; external transfer requires disclosure approval |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | **BENCHMARK** | Dynamic prompt-injection/utility-security evaluation; pin API and task version because the project warns of instability |
| [Inspect AI](https://github.com/UKGovernmentBEIS/inspect_ai) / [Inspect Evals](https://github.com/UKGovernmentBEIS/inspect_evals) | **BENCHMARK** | Highest-priority evaluation compatibility for CVEBench, CyberGym, Cybench, CyberSecEval, CTF, and agent-security tasks; SOVA evidence remains separate |
| [ACES](https://github.com/microsoft/ACES) / [ACESEvals](https://github.com/microsoft/ACESEvals) | **BENCHMARK/REFERENCE** | Study YAML-to-Inspect task compilation and scorer separation; do not fork a competing evaluation engine |
| [NIST CAISI cyber evals](https://github.com/usnistgov/caisi-cyber-evals) | **BENCHMARK** | Government-maintained composition of Inspect cybersecurity evaluations; preserve upstream tasks/scorers |
| [OASB](https://github.com/opena2a-org/oasb) | **BENCHMARK**, maturity caution | Adapter-based agent security scenarios and ATLAS mapping; early/self-reported project needs independent corpus and scorer audit |
| [Agent Security Bench](https://github.com/agiresearch/ASB) | **BENCHMARK CANDIDATE** | Scenario/defense coverage after licence, ground-truth, and leakage review |
| [OpenAgentSafety](https://github.com/Open-Agent-Safety/OpenAgentSafety) | **BENCHMARK CANDIDATE** | Realistic high-risk agent simulations through a maintained upstream runtime |
| [Damn Vulnerable AI Agent](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | **OWNED/LAB TARGET CANDIDATE** | Agent/MCP/A2A acceptance only after exact version, licence, and deterministic oracle audit |

## Standards and methodology sources

| Source | Decision | Use |
|---|---|---|
| [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final) | **REFERENCE** | Assessment planning, execution, analysis, limitations, and mitigation reporting |
| [OWASP WSTG](https://github.com/OWASP/wstg) | **REFERENCE DATA** | Web test taxonomy/procedures; CC BY-SA content stays outside Apache-licensed source code |
| [OWASP ASVS](https://github.com/OWASP/ASVS) | **REFERENCE DATA** | Requirement-to-test coverage mapping |
| [OWASP AISVS](https://github.com/OWASP/AISVS) | **REFERENCE DATA** | AI/agent orchestration, MCP, memory, supply-chain, and platform requirements |
| [OWASP AI Testing Guide](https://github.com/OWASP/www-project-ai-testing-guide) | **REFERENCE DATA** | Application/model/infrastructure/data testing taxonomy |
| [MITRE ATLAS](https://atlas.mitre.org/) | **REFERENCE DATA** | Versioned AI threat-technique mapping, not a complete methodology |
| [CWE](https://cwe.mitre.org/) / [CAPEC](https://capec.mitre.org/) | **REFERENCE DATA** | Weakness and attack-pattern interoperability under their terms of use |

The native playbook contract cites and maps these sources. It does not paste their
full prose into Apache-2.0 code or imply endorsement.

## Supply chain, static analysis, package, image, and binary tooling

| Project | Decision | Boundary |
|---|---|---|
| [Trivy](https://github.com/aquasecurity/trivy) | **ADAPTER** | Vulnerability, misconfiguration, secret, licence, and SBOM observations |
| [Syft](https://github.com/anchore/syft) | **ADAPTER** | Content-addressed SBOM generation |
| [Grype](https://github.com/anchore/grype) | **ADAPTER** | Vulnerability analysis of images/filesystems/SBOMs |
| [OSV-Scanner](https://github.com/google/osv-scanner) | **ADAPTER** | Lockfile/SBOM/source dependency vulnerability observations |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | **ADAPTER** | CLI only; do not assume the separately licensed GitHub Action is reusable |
| [Semgrep Community Edition](https://github.com/semgrep/semgrep) | **ADAPTER** | External CLI/rule execution; LGPL and documented cross-file limitations prohibit vendoring or overclaiming |
| [AFL++](https://github.com/AFLplusplus/AFLplusplus) | **ADAPTER** | Isolated fuzzing with exact harness/corpus/build provenance; AGPL tool remains external |
| [OSS-Fuzz](https://github.com/google/oss-fuzz) | **REFERENCE/BENCHMARK** | Multi-engine fuzzing architecture, sanitizer, corpus, and coverage practice |
| [angr](https://github.com/angr/angr) | **ADAPTER CANDIDATE** | Bounded binary analysis after platform/performance/licence review |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | **ADAPTER CANDIDATE** | Headless analysis under isolation; heavyweight and not a core dependency |
| [Prowler](https://github.com/prowler-cloud/prowler) | **ADAPTER CANDIDATE** | Cloud posture only with scoped read credentials and provider-specific evidence |
| [Kubescape](https://github.com/kubescape/kubescape) / [kube-bench](https://github.com/aquasecurity/kube-bench) | **ADAPTER CANDIDATE** | Kubernetes posture/CIS observations; cluster access is explicit and read-scoped by default |

## Benchmark and target sources

| Source | Decision | Notes |
|---|---|---|
| Inspect Evals cybersecurity registry | **BENCHMARK** | Broadest common evaluation adapter target; reports model capability, not SOVA product completeness |
| [EthiBench](https://github.com/ethiack/ethibench) | **BENCHMARK CANDIDATE** | Ground-truth penetration-testing cases; verify exact target licences and scoring |
| [Argus validation benchmarks](https://github.com/pensar-x/argus-validation-benchmarks) | **BENCHMARK CANDIDATE** | Broad containerized challenges; audit each image/task and oracle |
| PentestGPT/XBOW-compatible benchmark | **BENCHMARK CANDIDATE** | Useful agent comparison lane; equalize budgets/tools and preserve blind split |
| AI Goat and current SOVA fixtures | **OWNED ACCEPTANCE** | Deterministic engine/evidence proof only; not broad generalization |

Benchmark admission requires source/fixture provenance, licence, ground truth, scorer
review, contamination/leakage analysis, target safety, deterministic reset, and a
separate infrastructure-failure state.

## Isolation and hostile-agent execution

| Project | Decision | Boundary |
|---|---|---|
| [Firecracker](https://github.com/firecracker-microvm/firecracker) | **PRIMARY WORKER ARCHITECTURE** | Dedicated Linux/KVM host; one microVM/job; production jailer, unique identities, patched host/guest/microcode, cgroups/seccomp, no host mounts, bounded I/O, watchdog |
| [firecracker-containerd](https://github.com/firecracker-microvm/firecracker-containerd) | **REFERENCE/OPTIONAL ADAPTER** | Useful OCI/containerd lifecycle architecture; added control-plane complexity must earn itself |
| [Kata Containers](https://github.com/kata-containers/kata-containers) | **OPTIONAL BACKEND/HOLD UNTIL HARDENED** | OCI-compatible VM isolation, but 2026 advisories include escapes and annotation/config-path issues; exact-version pinning and annotation/mount lockdown required |
| [gVisor](https://github.com/google/gvisor) | **LOWER-ASSURANCE BACKEND** | Stronger container isolation through a userspace kernel; not equivalent to a VM for arbitrary hostile code |
| [Pipelock](https://github.com/luckyPipewrench/pipelock) | **REFERENCE / REJECT DIRECT ADAPTER** | Revision `1876e2326908ee57d764adf6a62f27a851c1d92a` confirms useful exact destination grants, dial-time DNS snapshots, signed receipts, and separate-proxy topology. Those exact grants are tied to Pipelock Guard's workload wrapper; its standalone proxy does not accept SOVA's immutable DNS-pin/receipt contract. SOVA reimplements only the compatible concepts in its separately pinned Rust mediator; no Pipelock code is copied or vendored. |
| Docker Desktop OCI executor | **COMPATIBILITY ONLY** | Current tested backend shares a VM kernel and remains outside the production hostile-agent claim |

Firecracker itself is not a complete worker. SOVA must build the authenticated job
protocol, image/provenance policy, network and secret brokers, host hardening,
attestation, evidence extraction, cleanup, monitoring, updates, and independent
review described by P5.

## Same-day independent second pass

The sources below were re-opened on 2026-08-26 after P0 rather than accepted from
the first inventory. The result did not reveal a safe drop-in universal pentest
engine. It did strengthen a few narrow architectural choices while confirming that
SOVA must own authority, evidence, coverage, replay, and claim discipline.

| Current upstream reviewed | Useful pattern | Guarded SOVA decision |
|---|---|---|
| [AutoPentest](https://github.com/bhavsec/autopentest-ai) | Explicit recon, analysis, exploitation, post-exploitation, and reporting tasks; parser/verification/context-compression seams | Reference task decomposition and prioritization only. Do not inherit universal-coverage or zero-false-positive claims; observations still need SOVA reproduction and evidence. |
| [PentAGI flow execution](https://github.com/vxcontrol/pentagi/blob/main/backend/docs/flow_execution.md) | Hierarchical flow/task/subtask execution and specialist-tool routing | Reference P2 planning and P3 orchestration. Model plans never grant authority or become trusted contracts. |
| [PentestGPT](https://github.com/GreyDGL/PentestGPT) | Reasoning/execution separation, state retention, telemetry, and benchmark discipline | Reference evaluation and context interfaces, not a core runtime dependency or evidence oracle. |
| [CAI](https://github.com/aliasrobotics/cai) | Agent/tool/handoff/turn/tracing/HITL abstractions | Research reference only pending exact licence review; do not copy incompatible code or let a handoff cross SOVA authority. |
| [ZAP](https://github.com/zaproxy/zaproxy), [Nuclei](https://github.com/projectdiscovery/nuclei), [Schemathesis](https://github.com/schemathesis/schemathesis) | Mature web/API discovery and test execution | External P3 adapters with pinned binaries/templates/schemas and raw receipts. Scanner output is an observation, not a finding. |
| [PyRIT](https://github.com/Azure/PyRIT), [garak](https://github.com/NVIDIA/garak), [promptfoo](https://github.com/promptfoo/promptfoo), [Inspect AI](https://github.com/UKGovernmentBEIS/inspect_ai) | AI attack orchestration, probes, assertions, and evaluation composition | Separate adapters/benchmark lanes; normalize outcomes through SOVA evidence and preserve provider/budget provenance. |
| [Trivy](https://github.com/aquasecurity/trivy), [Syft](https://github.com/anchore/syft), [Grype](https://github.com/anchore/grype), [OSV-Scanner](https://github.com/google/osv-scanner) | SBOM and package/image vulnerability evidence | Prefer upstream CLI/data formats and exact versions. Never vendor databases or present matches as independently reproduced vulnerabilities. |
| [Firecracker production guidance](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md), [Pipelock](https://github.com/luckyPipewrench/pipelock), [Kata Containers](https://github.com/kata-containers/kata-containers), [gVisor](https://github.com/google/gvisor) | VM/container isolation primitives, mediator-only egress, and operational hardening boundaries | Keep Firecracker as the P5 Linux/KVM foundation. Compile SOVA's own per-job TAP/veth/nftables boundary and separately pinned mediator. Pipelock is architectural provenance, not a direct runtime adapter; no current Windows hostile-agent claim. |

No third-party source code was copied into P1. The adopted ideas are contract and
seam patterns implemented against SOVA's existing canonical JSON, trace, capsule,
authority, and executor interfaces.

## P2 implementation decision

P2 retained the research conclusion: no reviewed autonomous-pentest repository was
copied or made a core dependency. SOVA implemented its own strict playbook and
compiler contracts, using the recurring task-graph, specialist-capability, phase,
and structured-result patterns only as architectural references. ZAP, Nuclei,
Schemathesis, PyRIT, garak, promptfoo, Trivy, Syft, Grype, OSV-Scanner, Gitleaks,
and Semgrep remain external P3 adapters rather than embedded methodology engines.

The native library's reference manifest pins NIST SP 800-115 Final (2008), PTES
web edition retrieved 2026-08-26, WSTG 4.2, ASVS 5.0.0, OWASP API Security 2023,
AISVS 1.0 at `78775233666a2022dcfb82037e5e029116955c00`, AI Testing Guide 1.0 at
`006e4e9ee060f2ca2176037499b824e47af5360e`, Agentic Top 10 2026, ATLAS
2026.07, CWE 4.20, and CAPEC 3.9. SOVA stores relationship mappings and source links, not copied
source prose or datasets. ATLAS 2026.07 is the P2 mapping pin; older SOVA taxonomy
artifacts remain separately versioned and are not silently rewritten.

## Immediate implementation order

1. P1 contracts and workflow/surface graph, with no external runtime dependency.
2. P2 native playbook contract/compiler and separated standards mappings.
3. P3 adapters beginning with Schemathesis, ZAP, Nuclei, PyRIT/garak/promptfoo,
   and supply-chain scanners.
4. P4 oracle calibration and coverage accounting before claiming scanner breadth.
5. P5 Linux/KVM hostile-agent worker; do not build a custom VMM.
6. P6 Inspect/OASB/AgentDojo and blinded multi-provider/target validation.

This order reuses mature projects where they are strongest while keeping SOVA's
implemented differentiator: authorized execution that ends in reproducible,
portable, replayable evidence rather than an unverified agent narrative.
