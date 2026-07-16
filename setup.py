"""Legacy setup.py shim for setuptools < 61 (PEP 621 pre-support).

Modern setuptools (>=61) reads all package metadata from pyproject.toml's
[project] table and ignores the args passed here. The explicit name/version/
packages are needed only so that older setuptools (e.g. the 59.5.0 pinned in
Yocto kirkstone) can build a wheel with correct metadata from the sdist --
without this shim the legacy build produces an UNKNOWN-0.0.0 wheel.

The version is read from src/ebus_service_discovery_client/__init__.py's
__version__ (the single source of truth) so the legacy build cannot drift from
the modern one.
"""

import re
from pathlib import Path

from setuptools import setup

version = re.search(
    r'^__version__ = "([^"]+)"',
    Path("src/ebus_service_discovery_client/__init__.py").read_text(encoding="utf-8"),
    re.M,
).group(1)

setup(
    name="ebus-service-discovery-client",
    version=version,
    package_dir={"": "src"},
    packages=["ebus_service_discovery_client"],
    package_data={"ebus_service_discovery_client": ["record.schema.json", "py.typed"]},
)
