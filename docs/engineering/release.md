<!-- status: implemented -->

# Release process

Topic 02 establishes the release mechanism; no package has been published.

## Version domains

- CLI/package: SemVer in `pyproject.toml`.
- `.sova`, `.sova-trace`, and every artifact family: independent spec versions.
- Methodologies and taxonomies: independent immutable ledger entries.
- Adapters: adapter contract plus supported upstream version range.

A CLI major version does not imply an artifact-schema major version.

## Candidate checklist

1. Complete the publication/IP, security, dual-use, licence, and provenance
   reviews.
2. Update `CHANGELOG.md`, methodology ledger, claims register, glossary, and
   compatibility declarations.
3. Confirm every supported historical stable schema still passes.
4. Run the full platform and Python matrix against the exact candidate commit.
5. Build the wheel and source distribution from a clean checkout.
6. Install the wheel in a clean environment and smoke-test `sova --version`.
7. Generate an SBOM and build-provenance attestation.
8. Sign an annotated tag and create an immutable GitHub release.
9. Publish through PyPI Trusted Publishing only after the `pypi` environment
   and package ownership are verified.
10. Verify the public package, hashes, provenance, documentation, and rollback
    instructions from an independent clean machine.

## Current automation

The release-candidate workflow builds and retains the Python distributions and
the pinned static Linux network mediator, emits separate timestamp-free
CycloneDX 1.6 SBOMs for their exact uv and Cargo closures, writes a stable
SHA-256 manifest, verifies exact release-tree membership, and creates
GitHub/Sigstore build-provenance attestations for every candidate file. It does
not publish to a package index.
This is intentional: a
pushed tag or candidate attestation is not a substitute for founder/publication
approval, and an attestation must still be verified by consumers.

Local offline verification:

```console
sova release verify-checksums ./dist ./dist/SHA256SUMS
```

Verify a downloaded candidate online with:

```console
gh attestation verify PATH/TO/ARTIFACT -R TRUSCOR/SOVA-OSS
```

The local MCP tool surface is separately pinned by `sova check --self`; a schema
or tool-description edit fails that self-check until the manifest digest is
reviewed and intentionally updated.

## Compatibility

Before a stable artifact change, run the complete reader/writer/migration matrix
in [ADR-0002](../decisions/0002-versioning-and-lossless-migration.md).
Experimental `0.x` changes still ship a changelog and best-effort migration.

## Security release

Follow `SECURITY.md`. Do not reveal an unpatched exploit through a regression
fixture, changelog entry, tag, artifact, SBOM, or failing public test before the
coordinated-disclosure gate.
