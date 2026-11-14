# SPDX-License-Identifier: Apache-2.0
"""Pinned Firecracker plan and cleanup-contract tests."""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

import pytest

from sova.formats import FormatError, validate_document
from sova.worker import firecracker as firecracker_module
from sova.worker.contracts import (
    ResourceLimits,
    WorkerAdmission,
    WorkerReadiness,
    assess_worker_attestation,
)
from sova.worker.firecracker import (
    FirecrackerHostPolicy,
    WorkerCleanupReceipt,
    build_firecracker_launch_plan,
    validate_cleanup_receipt,
)
from tests.support.worker import (
    digest,
    guest_keypair,
    host_path,
    worker_attestation,
    worker_manifest,
)


def _policy() -> FirecrackerHostPolicy:
    return FirecrackerHostPolicy(
        firecracker_binary=host_path("sova-worker", "bin", "firecracker"),
        jailer_binary=host_path("sova-worker", "bin", "jailer"),
        chroot_base=host_path("sova-worker", "jailer"),
        network_namespace_base=host_path("sova-worker", "netns"),
        content_store=host_path("sova-worker", "cas"),
        cgroup_base=host_path("sova-worker", "cgroup"),
        approved_firecracker_digest=digest("firecracker"),
        approved_jailer_digest=digest("jailer"),
    )


def _admission() -> WorkerAdmission:
    return assess_worker_attestation(
        worker_attestation(),
        expected_policy_digest=digest("policy"),
        expected_guest_kernel_digest=digest("kernel"),
        expected_root_filesystem_digest=digest("rootfs"),
    )


def test_launch_plan_enforces_jailer_mmio_cgroups_and_disposable_storage() -> None:
    manifest = worker_manifest(guest_keypair())
    plan = build_firecracker_launch_plan(manifest, _admission(), _policy(), identity_slot=17)
    mapping = plan.to_mapping()
    assert mapping["firecrackerVersion"] == "1.16.1"
    assert "--no-seccomp" not in plan.jailer_command
    assert mapping["jailer"]["seccompLevel"] == 2
    assert mapping["invariants"]["pciEnabled"] is False
    assert mapping["invariants"]["hostMountsAllowed"] is False
    assert {item[0] for item in plan.cgroup_values} == {"cpu.max", "memory.max", "pids.max"}
    assert "--new-pid-ns" in plan.jailer_command
    separator = plan.jailer_command.index("--")
    assert plan.jailer_command[separator + 1 :] == ("--api-sock", "/api.socket")
    assert plan.pid_file == "/firecracker.pid"
    assert Path(plan.cgroup_directory).parts[-2:] == ("sova", plan.vm_id)
    assert plan.jailer_command.count("--cgroup") == len(plan.cgroup_values)
    assert plan.jailer_command[plan.jailer_command.index("--parent-cgroup") + 1] == "sova"
    assert Path(plan.chroot_directory).parent.name == "firecracker"
    assert {item[2] for item in plan.staged_content} == {
        "copy-read-only",
        "copy-disposable-writable",
    }
    validate_document(mapping)


def test_offline_plan_omits_network_device_instead_of_emitting_zero_rate_limit() -> None:
    manifest = replace(
        worker_manifest(guest_keypair()),
        limits=ResourceLimits(network_connection_limit=0, network_bytes=0),
    )
    plan = build_firecracker_launch_plan(manifest, _admission(), _policy(), identity_slot=17)
    assert all(
        path != "/network-interfaces/eth0" for path, _payload in plan.firecracker_api_requests
    )
    assert plan.firecracker_api_requests[-1] == ("/actions", {"action_type": "InstanceStart"})


def test_launch_plan_uses_exclusive_host_allocated_identity_slots() -> None:
    manifest = worker_manifest(guest_keypair())
    first = build_firecracker_launch_plan(manifest, _admission(), _policy(), identity_slot=1)
    second = build_firecracker_launch_plan(manifest, _admission(), _policy(), identity_slot=2)
    assert (first.uid, first.gid) != (second.uid, second.gid)


def test_launch_plan_refuses_unavailable_attestation() -> None:
    admission = WorkerAdmission(WorkerReadiness.UNAVAILABLE, ("kvm-unavailable",), digest("a"))
    with pytest.raises(FormatError, match="not admitted"):
        build_firecracker_launch_plan(
            worker_manifest(guest_keypair()), admission, _policy(), identity_slot=1
        )


def test_cleanup_receipt_must_bind_exact_job_and_every_cleanup_check() -> None:
    plan = build_firecracker_launch_plan(
        worker_manifest(guest_keypair()), _admission(), _policy(), identity_slot=1
    )
    complete = WorkerCleanupReceipt(
        job_id=plan.job_id,
        vm_id=plan.vm_id,
        completed_at="2026-08-27T10:12:00Z",
        process_terminated=True,
        api_socket_removed=True,
        cgroup_removed=True,
        network_namespace_removed=True,
        chroot_removed=True,
        writable_layer_removed=True,
        secret_broker_revoked=True,
    )
    validate_cleanup_receipt(complete, plan)
    validate_document(complete.to_mapping())
    incomplete = WorkerCleanupReceipt(
        job_id=plan.job_id,
        vm_id=plan.vm_id,
        completed_at="2026-08-27T10:12:00Z",
        process_terminated=True,
        api_socket_removed=True,
        cgroup_removed=False,
        network_namespace_removed=True,
        chroot_removed=True,
        writable_layer_removed=True,
        secret_broker_revoked=True,
    )
    with pytest.raises(FormatError, match="incomplete"):
        validate_cleanup_receipt(incomplete, plan)
    with pytest.raises(FormatError, match="another job"):
        validate_cleanup_receipt(
            replace(complete, job_id="job:other"),
            plan,
        )


def test_host_policy_rejects_relative_paths_identity_ranges_and_seccomp_override() -> None:
    base = _policy()
    mutations = (
        {"firecracker_binary": Path("relative")},
        {"uid_base": 1},
        {"gid_base": 1},
        {"seccomp_level": 0},
    )
    for changes in mutations:
        with pytest.raises(FormatError):
            replace(base, **changes)


def test_launch_plan_rejects_invalid_identity_slot_and_cas_digest() -> None:
    manifest = worker_manifest(guest_keypair())
    with pytest.raises(FormatError, match="negative"):
        build_firecracker_launch_plan(manifest, _admission(), _policy(), identity_slot=-1)
    with pytest.raises(FormatError, match="exceeds"):
        build_firecracker_launch_plan(manifest, _admission(), _policy(), identity_slot=600_001)
    with pytest.raises(FormatError, match="approved CAS key"):
        firecracker_module._cas_path(host_path("cas"), "bad")


def test_launch_plan_bounds_jailer_id_and_writable_seed() -> None:
    manifest = replace(worker_manifest(guest_keypair()), job_id=f"job:{'a' * 180}")
    plan = build_firecracker_launch_plan(manifest, _admission(), _policy(), identity_slot=1)
    assert len(plan.vm_id) <= 64
    assert re.fullmatch(r"[A-Za-z0-9-]+", plan.vm_id)
    oversized = replace(
        manifest,
        limits=replace(manifest.limits, writable_disk_bytes=1),
    )
    with pytest.raises(FormatError, match="disk budget"):
        build_firecracker_launch_plan(oversized, _admission(), _policy(), identity_slot=1)


def test_host_policy_retains_platform_absolute_cgroup_default() -> None:
    policy = FirecrackerHostPolicy(
        firecracker_binary=host_path("sova-worker", "bin", "firecracker"),
        jailer_binary=host_path("sova-worker", "bin", "jailer"),
        chroot_base=host_path("sova-worker", "jailer"),
        network_namespace_base=host_path("sova-worker", "netns"),
        content_store=host_path("sova-worker", "cas"),
        approved_firecracker_digest=digest("firecracker"),
        approved_jailer_digest=digest("jailer"),
    )
    assert policy.cgroup_base.is_absolute()
