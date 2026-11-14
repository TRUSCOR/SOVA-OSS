<!-- status: implemented -->

# Installation and initialization

SOVA OSS is published on PyPI as `sova-oss` and needs Python 3.11 to 3.14 on
Windows, macOS or Linux:

```console
pip install sova-oss                 # record, verify, show, compare, audit
pip install "sova-oss[agentdojo]"    # adds rerun, matrix and calibrate
sova --version
```

To install the command on its own, isolated from your projects, use
`uv tool install sova-oss` or `pipx install sova-oss`. What is frozen and what is
experimental in this release is listed in [api-stability](../governance/api-stability.md).

No SOVA account, hosted service, provider key, model, or network connection is
required for the deterministic core. The package includes the Ed25519 signing
dependency needed by the signed demo and trace workflows; the only extra is
`agentdojo`, which re-running recorded findings needs.

To work on SOVA itself, use a source checkout:

```console
git clone https://github.com/TRUSCOR/SOVA-OSS.git
cd SOVA-OSS
uv sync --locked
uv run sova --version
```

The `uv run` prefix in the commands below is for a source checkout; with the
package installed, run `sova` directly.

Initialize a local data directory:

```console
uv run sova init .sova-local --provider none
uv run sova doctor .sova-local
```

`init` creates a random local MCP control key without printing it. Provider
selection records only an environment-variable name; it never copies a key into
SOVA configuration. Supported selections are `none`, `openai`, `anthropic`,
`google`, `openrouter`, `ollama`, and `custom`. Provider-backed features remain
optional.

To select an already verified local registry mirror without network access:

```console
uv run sova init .sova-local --registry PATH/TO/LOCAL/MIRROR
```

Windows, macOS, and Linux are exercised in CI on CPython 3.11-3.14. The exact
candidate commit and CI result, not this sentence alone, determine support.
