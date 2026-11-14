# SPDX-License-Identifier: Apache-2.0
"""Strict dedicated-worker deployment policy parsing tests."""

from __future__ import annotations

from copy import deepcopy

import pytest

from sova.formats import FormatError, canonical_json_bytes
from sova.worker.deployment import read_worker_deployment_policy
from tests.support.worker import digest, host_path


def _host(*parts: str) -> str:
    return host_path("worker", *parts).as_posix()


def _mapping() -> dict[str, object]:
    return {
        "artifactType": "sova.worker-deployment-policy",
        "schemaVersion": "0.2.0",
        "status": "configured-not-attested",
        "workerId": "worker:dedicated-01",
        "firecrackerVersion": "1.16.1",
        "hostPaths": {
            "firecrackerBinary": _host("bin", "firecracker"),
            "jailerBinary": _host("bin", "jailer"),
            "chrootBase": _host("jailer"),
            "networkNamespaceBase": _host("netns"),
            "contentStore": _host("cas"),
            "cgroupBase": _host("cgroup"),
            "ipBinary": _host("bin", "ip"),
            "nftBinary": _host("bin", "nft"),
            "setprivBinary": _host("bin", "setpriv"),
            "networkMediatorBinary": _host("bin", "mediator"),
            "networkStateDirectory": _host("network-state"),
            "identityLeaseDirectory": _host("identity-leases"),
            "hostKernelImage": _host("host-kernel"),
            "microcodeImage": _host("microcode"),
            "guestKernelImage": _host("guest-kernel"),
            "rootFilesystemImage": _host("rootfs.ext4"),
            "advisorySnapshot": _host("advisories.json"),
        },
        "network": {
            "egressInterface": "eth0",
            "mediatorUidBase": 700_000,
            "mediatorGidBase": 700_000,
            "proxyPort": 8888,
        },
        "pins": {
            "firecrackerDigest": digest("firecracker"),
            "jailerDigest": digest("jailer"),
            "ipDigest": digest("ip"),
            "nftDigest": digest("nft"),
            "setprivDigest": digest("setpriv"),
            "networkMediatorDigest": digest("mediator"),
            "hostKernelDigest": digest("host-kernel"),
            "microcodeDigest": digest("microcode"),
            "guestKernelDigest": digest("guest-kernel"),
            "rootFilesystemDigest": digest("rootfs"),
            "advisorySnapshotDigest": digest("advisories"),
        },
        "requiredControls": {
            "dedicatedLinuxHost": True,
            "kvm": True,
            "cgroupV2": True,
            "swapDisabled": True,
            "defaultSeccomp": True,
            "uniqueUidGidPerJob": True,
            "rootOwnedPaths": True,
            "hostMountsAllowed": False,
            "pciEnabled": False,
            "ambientGuestNetwork": False,
            "mediatorOnlyEgress": True,
            "independentReviewRequired": True,
        },
    }


def test_configured_policy_loads_every_pinned_boundary() -> None:
    raw = canonical_json_bytes(_mapping())
    policy = read_worker_deployment_policy(raw)
    assert policy.worker_id == "worker:dedicated-01"
    assert policy.firecracker.approved_firecracker_digest == digest("firecracker")
    assert policy.network.approved_mediator_digest == digest("mediator")
    assert policy.network.proxy_port == 8888
    assert policy.identity_lease_directory.name == "identity-leases"
    assert policy.source_digest.startswith("sha256:")


def test_template_unknown_fields_and_weakened_controls_fail_closed() -> None:
    template = _mapping()
    template["status"] = "template-not-admitted"
    with pytest.raises(FormatError, match="template"):
        read_worker_deployment_policy(canonical_json_bytes(template))

    unknown = _mapping()
    unknown["unreviewedOption"] = True
    with pytest.raises(FormatError, match="fields must be exact"):
        read_worker_deployment_policy(canonical_json_bytes(unknown))

    weakened = deepcopy(_mapping())
    controls = weakened["requiredControls"]
    assert isinstance(controls, dict)
    controls["ambientGuestNetwork"] = True
    with pytest.raises(FormatError, match="weakened"):
        read_worker_deployment_policy(canonical_json_bytes(weakened))


def test_policy_types_pins_and_paths_fail_closed() -> None:
    wrong_object = _mapping()
    wrong_object["network"] = []
    with pytest.raises(FormatError, match="object"):
        read_worker_deployment_policy(canonical_json_bytes(wrong_object))

    wrong_string = _mapping()
    wrong_string["workerId"] = 7
    with pytest.raises(FormatError, match="string"):
        read_worker_deployment_policy(canonical_json_bytes(wrong_string))

    wrong_integer = deepcopy(_mapping())
    network = wrong_integer["network"]
    assert isinstance(network, dict)
    network["proxyPort"] = True
    with pytest.raises(FormatError, match="integer"):
        read_worker_deployment_policy(canonical_json_bytes(wrong_integer))

    wrong_pin = deepcopy(_mapping())
    pins = wrong_pin["pins"]
    assert isinstance(pins, dict)
    pins["hostKernelDigest"] = "bad"
    with pytest.raises(FormatError, match="pin"):
        read_worker_deployment_policy(canonical_json_bytes(wrong_pin))

    relative_path = deepcopy(_mapping())
    paths = relative_path["hostPaths"]
    assert isinstance(paths, dict)
    paths["identityLeaseDirectory"] = "relative/leases"
    with pytest.raises(FormatError, match="absolute"):
        read_worker_deployment_policy(canonical_json_bytes(relative_path))
