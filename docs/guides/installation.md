<!-- status: implemented -->

# Installation and initialization

SOVA OSS is pre-alpha. The canonical source-checkout path is:

```console
git clone https://github.com/TRUSCOR/SOVA-OSS.git
cd SOVA-OSS
uv sync --locked
uv run sova --version
```

No SOVA account, hosted service, provider key, model, or network connection is
required for the deterministic core. The canonical package includes the
Ed25519 signing dependency needed by the signed demo and trace workflows; there
is no second “full” package extra to discover. A package-index command is intentionally
not documented until an official package is published and verified.

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
