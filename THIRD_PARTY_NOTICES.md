# Third-party dependency and tool notices

SOVA OSS `0.1.0` uses JSON Schema 2020-12 validators and an optional signing
extra. The following projects support the runtime, build, test, review, or
automation workflow and are not vendored into this repository.

| Project | Role | Licence | Source |
|---|---|---|---|
| `hatchling` | PEP 517 build backend | MIT | [PyPA Hatch](https://github.com/pypa/hatch) |
| `agentdojo` 0.1.35 | Optional `sova-oss[agentdojo]` extra: fresh runs of recorded AgentDojo findings (`sova rerun`, `sova matrix`) | MIT | [ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo) |
| `openai` / `anthropic` | Provider SDKs installed with the `agentdojo` extra; used only by `sova rerun` and `sova matrix` | Apache-2.0 | [openai/openai-python](https://github.com/openai/openai-python) / [anthropics/anthropic-sdk-python](https://github.com/anthropics/anthropic-sdk-python) |
| `cryptography` | Optional Ed25519 signing and verification; development tests | Apache-2.0 or BSD-3-Clause | [pyca/cryptography](https://github.com/pyca/cryptography) |
| `hypothesis` | Development-only property-based testing | MPL-2.0 | [HypothesisWorks/hypothesis](https://github.com/HypothesisWorks/hypothesis) |
| `jsonschema` | JSON Schema 2020-12 runtime validation | MIT | [python-jsonschema/jsonschema](https://github.com/python-jsonschema/jsonschema) |
| `jsonschema-rs` | High-throughput JSON Schema 2020-12 runtime validation; parity-tested against `jsonschema` | MIT | [Stranger6667/jsonschema](https://github.com/Stranger6667/jsonschema) |
| `mypy` | Static type checking | MIT | [python/mypy](https://github.com/python/mypy) |
| `pip` | Development environment and isolated wheel-install tooling | MIT | [PyPA pip](https://github.com/pypa/pip) |
| `pip-audit` | Python dependency vulnerability audit | Apache-2.0 | [pypa/pip-audit](https://github.com/pypa/pip-audit) |
| `pre-commit` | Local quality-hook runner | MIT | [pre-commit/pre-commit](https://github.com/pre-commit/pre-commit) |
| `pytest` | Test runner | MIT | [pytest-dev/pytest](https://github.com/pytest-dev/pytest) |
| `pytest-cov` | Coverage integration | MIT | [pytest-dev/pytest-cov](https://github.com/pytest-dev/pytest-cov) |
| `ruff` | Formatting, linting, and Python security rules | MIT | [astral-sh/ruff](https://github.com/astral-sh/ruff) |
| `types-jsonschema` | Development-only type information for jsonschema | Apache-2.0 | [python/typeshed](https://github.com/python/typeshed) |
| `uv` | Contributor environment, lockfile, and build runner | Apache-2.0 or MIT | [astral-sh/uv](https://github.com/astral-sh/uv) |
| `websocket-client` | Development-only installed-Chrome replay acceptance transport | Apache-2.0 | [websocket-client/websocket-client](https://github.com/websocket-client/websocket-client) |
| `httparse` | Strict bounded HTTP/1 request parsing in the worker mediator | Apache-2.0 or MIT | [seanmonstar/httparse](https://github.com/seanmonstar/httparse) |
| `serde` / `serde_json` | Typed and canonical JSON parsing/encoding in the worker mediator | Apache-2.0 or MIT | [serde-rs/serde](https://github.com/serde-rs/serde) / [serde-rs/json](https://github.com/serde-rs/json) |
| `sha2` | SHA-256 policy and receipt content bindings in the worker mediator | Apache-2.0 or MIT | [RustCrypto/hashes](https://github.com/RustCrypto/hashes) |
| `time` 0.3.47 | Strict UTC expiry parsing in the worker mediator; fixed release for RUSTSEC-2026-0009 | Apache-2.0 or MIT | [time-rs/time](https://github.com/time-rs/time) |
| `url` | Absolute HTTP/WebSocket target parsing in the worker mediator | Apache-2.0 or MIT | [servo/rust-url](https://github.com/servo/rust-url) |
| `cargo-audit` 0.22.2 | RustSec dependency-advisory enforcement in CI | Apache-2.0 or MIT | [rustsec/rustsec](https://github.com/rustsec/rustsec) |
| `actions/checkout` | GitHub Actions checkout | MIT | [actions/checkout](https://github.com/actions/checkout) |
| `actions/dependency-review-action` | Pull-request dependency review | MIT | [actions/dependency-review-action](https://github.com/actions/dependency-review-action) |
| `actions/upload-artifact` | Release-candidate artifact retention | MIT | [actions/upload-artifact](https://github.com/actions/upload-artifact) |
| `astral-sh/setup-uv` | Reproducible CI toolchain setup | MIT | [astral-sh/setup-uv](https://github.com/astral-sh/setup-uv) |
| `github/codeql-action` | GitHub code scanning | MIT | [github/codeql-action](https://github.com/github/codeql-action) |
| `gitleaks/gitleaks-action` | CI secret scanning | Gitleaks Action licence | [gitleaks/gitleaks-action](https://github.com/gitleaks/gitleaks-action) |
| Contributor Covenant 2.1 | Community code-of-conduct text | CC BY 4.0 | [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct.html) |

Transitive Python dependencies and exact versions are recorded in `uv.lock`.
The mediator's complete Rust graph is recorded in its `Cargo.lock`; package
metadata reports Apache-2.0, MIT, Unicode-3.0, or Unlicense licence identifiers,
with dual-licence choices resolved under the applicable permissive option and no
missing licence field. The graph and selected terms must be re-audited on every lockfile change.
GitHub Actions are pinned to
immutable full commit SHAs and are updated through reviewed Dependabot pull requests.

## Referenced classification catalogs

The native SOVA taxonomy contains factual identifiers, titles, relationships,
catalog versions, and links for interoperability. It does not claim endorsement
by the catalog owners.

- MITRE ATLAS data: Copyright 2021–2025 The MITRE Corporation, licensed under
  Apache License 2.0. SOVA mappings pin ATLAS data release 5.6.0.
- CWE: Copyright © 2006–2026 The MITRE Corporation. CWE and its associated
  references are used under the
  [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html). CWE is a
  trademark of The MITRE Corporation.
- CAPEC: Copyright © The MITRE Corporation. CAPEC identifiers and references
  are used under the
  [CAPEC Terms of Use](https://capec.mitre.org/about/termsofuse.html). CAPEC is
  a trademark of The MITRE Corporation.
- OWASP Top 10 for Agentic Applications 2026: © OWASP Foundation, licensed
  under CC BY-SA 4.0. SOVA uses the published ASI identifiers and titles as
  versioned mappings and links to the original work.

Before adding a runtime dependency, contributor tooling, fixture, copied code,
model, dataset, binary, or action:

1. verify its source, licence, authorship, redistribution terms, and security
   posture;
2. record it here or in the fixture/dataset provenance ledger;
3. regenerate and review `uv.lock`;
4. run the dependency, secret, licence, and public-boundary checks;
5. preserve any required licence or notice text in the distributed artifact.

This ledger is an engineering record, not legal advice. Unclear or incompatible
terms block the dependency until qualified review resolves them.
