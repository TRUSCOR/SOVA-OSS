# SPDX-License-Identifier: Apache-2.0
"""Unit contracts for release-version checks."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _check_tag(tag: str) -> subprocess.CompletedProcess[str]:
    script = Path(__file__).parents[2] / "scripts" / "check_release_version.py"
    return subprocess.run(
        [sys.executable, str(script), tag],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_release_tag_must_match_package_version() -> None:
    accepted = _check_tag("v0.1.1")
    rejected = _check_tag("v0.1.0")

    assert accepted.returncode == 0
    assert accepted.stdout == "RELEASE_VERSION_CHECK=PASS: v0.1.1\n"
    assert rejected.returncode == 1
    assert "RELEASE_VERSION_CHECK=FAILED" in rejected.stdout
