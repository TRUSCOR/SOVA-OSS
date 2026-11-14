# Internet deployment boundary

This directory is a hardened starting blueprint, not evidence of a production
deployment. The only supported build and launch path is `preflight.py`: it
validates every image reference, validates Compose's fully interpolated image
set, and refuses mutable tags. Raw `docker compose up` is not the documented
launch path.

The edge proxy shares the registry container's network namespace, so the
Python reference service remains bound to loopback and Caddy alone terminates
TLS on port 443. The Caddy request limit is exactly `50331648` bytes (48 MiB),
matching `CommunityServiceLimits.max_body_bytes`; this permits one bounded
encoded submission containing the service's two maximum-size evidence files.
The `request_body` directive requires Caddy 2.10 or newer, still pinned by
digest.

## Build the SOVA runtime image

Build the wheel first with `uv build`. Then invoke the shipped recipe through
the validator, supplying an immutable Python base and an explicit temporary
tag:

```console
python deploy/community/preflight.py build \
  --base-image python:3.11-slim@sha256:REPLACE_WITH_64_LOWERCASE_HEX \
  --wheel dist/sova_oss-0.1.0-py3-none-any.whl \
  --local-tag ghcr.io/OWNER/sova-oss:0.1.0
```

`build` rejects a tag-only base, sends only `dist/*.whl` through the
deny-by-default Docker build context, and inspects the finished image for the
numeric `65532:65532` user, `/var/lib/sova` working directory, `sova`
entrypoint, and runtime-data label. Dependency resolution during this
pre-alpha recipe is not a reproducible-build claim; retain the wheel, base
digest, image SBOM, build provenance, and vulnerability scan with the release.

Push that temporary tag to an operator-controlled registry, obtain the
registry-reported manifest digest, and use only its final
`repository[:tag]@sha256:<64 lowercase hex>` reference for `SOVA_IMAGE`. A tag
without its digest, even one just built by this script, is deliberately
rejected by `check` and `up`.

## Prepare operator-owned inputs outside the checkout

Never put a bearer token, private key, accepted trace, or client evidence in
this repository. Create an absolute directory outside the source checkout,
then create these two files there:

- `service.token`, created once with `sova registry init-service
  ABSOLUTE_OPERATOR_DIR/service.token`;
- `methodology.md`, a non-empty UTF-8 methodology snapshot reviewed by the
  operator.

Set `SOVA_OPERATOR_DIR` to that absolute directory. Preflight rejects a
relative path, a path inside the repository, symlinks, an invalid token file,
or an empty methodology. It validates the token locally but never prints it,
places it in the report, passes its contents through the environment, or
copies it into an image.

The host files are mounted only into the no-network initializer. That bounded
stage uses `DAC_READ_SEARCH` solely to read a correctly protected host token,
installs both files as UID/GID `65532:65532` with mode `0400` into the separate
`registry-operator` volume, and exits without printing their contents. The
long-running registry sees that staged volume read-only at
`/run/sova/operator`; it never receives the host bind and cannot rewrite the
staged token. It is not copied into the image, an environment variable, or a
preflight report, but it **is** copied into persistent Docker volume
`sova-community_registry-operator`; any Docker daemon administrator can read
that volume. Rotation overwrites the staged files on the next successful
`preflight.py up`. Exclude this volume from ordinary data backups.

Set the remaining environment variables:

| Variable | Required value |
| --- | --- |
| `SOVA_IMAGE` | Pushed SOVA image as exact `repository[:tag]@sha256:<64 lowercase hex>` |
| `CADDY_IMAGE` | Caddy 2.10+ as exact `repository[:tag]@sha256:<64 lowercase hex>` |
| `SOVA_TRUSTED_EVIDENCE_KEY_ID` | Exact `sha256:<64 lowercase hex>` signer key ID |
| `SOVA_COMMUNITY_DOMAIN` | Lowercase public DNS name, without scheme, port, path, or wildcard |
| `SOVA_OPERATOR_DIR` | Absolute external directory described above |

## Validate, then launch

```console
python deploy/community/preflight.py check
python deploy/community/preflight.py up
```

`check` validates operator inputs, runs `docker compose config`, asks Compose
for its resolved images, and requires that set to equal the two already
validated digest references. `up` repeats those checks, pulls the exact
digests, verifies Docker's local `RepoDigests`, and then starts with
`--pull never --wait`.

The preflight fixes the Compose project name to `sova-community`, making the
secret-bearing volume name stable. During credential-recovery or decommission,
stop the stack with all five validated environment variables still set, then
remove only the exact operator volume:

```console
docker compose --project-name sova-community --file deploy/community/compose.yaml down
docker volume rm sova-community_registry-operator
```

The second command irreversibly removes the staged token and methodology copy;
verify the exact name before running it. Do not use `down --volumes` unless the
operator also intends to destroy registry data and Caddy state. A later
`preflight.py up` recreates and repopulates the operator volume from the
external source directory.

The SOVA image owns `/var/lib/sova` as numeric UID/GID `65532:65532`. On every
launch, a one-shot, no-network initializer receives only the narrowly required
`CHOWN`, `DAC_OVERRIDE`, `DAC_READ_SEARCH`, and `FOWNER` capabilities, repairs
the named data volume's ownership, stages the two operator files into their
separate protected volume, writes an ownership-contract marker, and exits. The
long-running registry then starts non-root with all capabilities dropped, a
read-only root filesystem, only the data volume writable, and the operator
volume read-only. Its Compose command starts with `registry serve` because the
image entrypoint is already `sova`.

## External production gates

The exact operational receipt contract, backup/restore rehearsal, rollback, and
incident checklist are in [OPERATIONS.md](./OPERATIONS.md). Start from
`beta-policy.example.json`, replace every placeholder outside the public checkout,
and bind every receipt to that policy's digest and the exact artifact manifest.

Before an Internet deployment, an operator must add independently reviewed
identity and authorization, moderation, abuse handling, backups and restore
tests, monitoring, alert escalation, DDoS controls, key rotation, revocation,
privacy and retention policy, regional compliance, disaster recovery, and a
documented incident-response owner. Run it first with synthetic capsules only.
Public hosting remains an external acceptance gate until a real operator has
deployed, tested, and attested this stack.
