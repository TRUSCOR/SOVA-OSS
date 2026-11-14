# SPDX-License-Identifier: Apache-2.0
"""Deterministic P5 worker fixtures shared across unit and integration tests."""

from __future__ import annotations

import os
from pathlib import Path, PosixPath
from typing import TYPE_CHECKING

from sova.formats import sha256_digest
from sova.trace.integrity import Ed25519Keypair, generate_ed25519_keypair
from sova.worker.contracts import (
    FIRECRACKER_VERSION,
    ContentReference,
    NetworkRule,
    ResourceLimits,
    SecretGrant,
    WorkerAttestation,
    WorkerBackend,
    WorkerJobManifest,
)
from sova.worker.identity import IdentitySlotLeaseTable

if TYPE_CHECKING:
    import pytest

# Host-policy fixtures need paths that are absolute on the machine running the
# test: ``C:/...`` is relative on POSIX and ``/...`` is drive-relative on Windows.
_HOST_ANCHOR = Path("C:/") if os.name == "nt" else Path("/")


def digest(label: str) -> str:
    return sha256_digest(label.encode("utf-8"))


def host_path(*parts: str) -> Path:
    """Return a platform-absolute worker host path that tests never create."""
    return _HOST_ANCHOR.joinpath(*parts)


def owner_uid() -> int:
    """Return the owner of files this process creates; Windows reports zero."""
    geteuid = getattr(os, "geteuid", None)
    return 0 if geteuid is None else int(geteuid())


_STAT_SEQUENCE_FIELDS = frozenset(
    {"st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size"}
)


class _RootOwnedPath(PosixPath):
    """Report files owned by this unprivileged test process as owned by root.

    Only the owner is translated. File type, link count, and permission bits stay
    the real on-disk values, so the lease reader's remaining checks still run.
    """

    def lstat(self) -> os.stat_result:
        observed = super().lstat()
        if observed.st_uid != owner_uid():
            return observed
        fields = list(observed)
        fields[4] = 0  # st_uid
        # The mapping may only carry fields beyond the sequence part (Python 3.13+
        # rejects duplicates), e.g. float/ns timestamps and st_blksize.
        named = {
            name: getattr(observed, name)
            for name in dir(observed)
            if name.startswith("st_") and name not in _STAT_SEQUENCE_FIELDS
        }
        return os.stat_result(fields, named)


def unprivileged_lease_root(root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Let lease-semantics tests run without root on POSIX hosts.

    Production lease roots must be a root-owned, non-writable directory chain. A
    non-root test process cannot create one, so on POSIX this stubs the ancestor
    walk and translates this process's own uid to root for lease files. Both
    ownership checks are exercised unmodified by dedicated identity tests. On
    Windows the checks do not apply and the root is returned unchanged.
    """
    if os.name != "posix":
        return root
    monkeypatch.setattr(IdentitySlotLeaseTable, "_require_root_controlled", lambda _self: None)
    return _RootOwnedPath(root)


def guest_keypair() -> Ed25519Keypair:
    return generate_ed25519_keypair()


def worker_manifest(
    guest_key: Ed25519Keypair,
    *,
    network_bytes: int = 4096,
    network_connections: int = 2,
    output_bytes: int = 1024 * 1024,
) -> WorkerJobManifest:
    return WorkerJobManifest(
        job_id="job:p5-fixture",
        issued_at="2026-08-27T10:00:00Z",
        expires_at="2026-08-27T10:15:00Z",
        target_profile_digest=digest("target"),
        authorization_decision_digest=digest("authority"),
        methodology_plan_digest=digest("methodology"),
        guest_output_key_digest=sha256_digest(guest_key.public_key),
        guest_kernel=ContentReference(
            "guest-kernel", digest("kernel"), 1024, "application/octet-stream"
        ),
        root_filesystem=ContentReference(
            "root-filesystem", digest("rootfs"), 2048, "application/octet-stream"
        ),
        writable_layer_seed=ContentReference(
            "writable-seed", digest("writable"), 4096, "application/octet-stream"
        ),
        inputs=(ContentReference("target-input", digest("input"), 256, "application/zip"),),
        network_rules=(NetworkRule("example.com", 443, "tcp", ("1.1.1.1",)),),
        secret_grants=(SecretGrant("target-api", "https://example.com", "2026-08-27T10:10:00Z"),),
        output_schema_ids=("sova.worker-network-receipt",),
        limits=ResourceLimits(
            timeout_seconds=600,
            output_bytes=output_bytes,
            network_connection_limit=network_connections,
            network_bytes=network_bytes,
        ),
    )


def worker_attestation(
    *,
    dedicated: bool = True,
    wsl: bool = False,
    reviewed: bool = False,
    kvm: bool = True,
) -> WorkerAttestation:
    return WorkerAttestation(
        worker_id="worker:p5-fixture",
        measured_at="2026-08-27T09:55:00Z",
        backend=WorkerBackend.FIRECRACKER,
        dedicated_linux_host=dedicated,
        wsl_environment=wsl,
        kvm_available=kvm,
        cgroup_v2=True,
        swap_disabled=True,
        default_seccomp=True,
        unique_uid_gid_per_job=True,
        host_paths_root_owned=True,
        firecracker_version=FIRECRACKER_VERSION,
        firecracker_digest=digest("firecracker"),
        jailer_digest=digest("jailer"),
        host_kernel_digest=digest("host-kernel"),
        microcode_digest=digest("microcode"),
        guest_kernel_digest=digest("kernel"),
        root_filesystem_digest=digest("rootfs"),
        policy_digest=digest("policy"),
        advisory_snapshot_digest=digest("advisories"),
        independent_review_receipt=digest("review") if reviewed else None,
    )


__all__ = [
    "digest",
    "guest_keypair",
    "host_path",
    "owner_uid",
    "unprivileged_lease_root",
    "worker_attestation",
    "worker_manifest",
]
