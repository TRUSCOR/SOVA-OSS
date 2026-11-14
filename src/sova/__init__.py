# SPDX-License-Identifier: Apache-2.0
"""SOVA OSS public Python package."""

from importlib.metadata import PackageNotFoundError, version

_DISTRIBUTION_NAME = "sova-oss"
_SOURCE_FALLBACK_VERSION = "0.1.0"

try:
    __version__ = version(_DISTRIBUTION_NAME)
except PackageNotFoundError:
    __version__ = _SOURCE_FALLBACK_VERSION

__all__ = ["__version__"]
