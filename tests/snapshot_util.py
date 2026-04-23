# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Shared helpers for capa freeze snapshot fixtures.

Used by `scripts/generate-freeze-snapshots.py` and `tests/test_freeze_snapshots.py`.
The snapshots live under `tests/fixtures/freezes/`; each entry in `manifest.json`
identifies a sample in the `tests/data/` submodule plus the corresponding `.frz`
file and metadata.
"""

from __future__ import annotations

import json
import hashlib
from typing import Any, Optional
from pathlib import Path
from dataclasses import dataclass

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
TESTS_DATA_DIR = TESTS_DIR / "data"
FREEZES_DIR = TESTS_DIR / "fixtures" / "freezes"
MANIFEST_PATH = FREEZES_DIR / "manifest.json"


@dataclass(frozen=True)
class Snapshot:
    """One entry in the freeze snapshot manifest."""

    name: str
    sample: str
    freeze: str
    format: Optional[str] = None
    backend: Optional[str] = None
    os: Optional[str] = None
    capa_version: Optional[str] = None
    generated_at_commit: Optional[str] = None
    sha256: Optional[str] = None

    @property
    def sample_path(self) -> Path:
        return TESTS_DATA_DIR / self.sample

    @property
    def freeze_path(self) -> Path:
        return FREEZES_DIR / self.freeze


@dataclass
class Manifest:
    version: int
    description: str
    snapshots: list[Snapshot]

    @classmethod
    def load(cls, path: Path = MANIFEST_PATH) -> "Manifest":
        doc = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            version=doc.get("version", 1),
            description=doc.get("description", ""),
            snapshots=[Snapshot(**entry) for entry in doc["snapshots"]],
        )

    def save(self, path: Path = MANIFEST_PATH) -> None:
        doc = {
            "version": self.version,
            "description": self.description,
            "snapshots": [_snapshot_to_dict(s) for s in self.snapshots],
        }
        path.write_text(json.dumps(doc, indent=4) + "\n", encoding="utf-8")


def _snapshot_to_dict(s: Snapshot) -> dict[str, Any]:
    # Emit a stable, human-friendly key order, and omit keys that are None so
    # optional overrides like `format` / `backend` / `os` don't clutter the file.
    out: dict[str, Any] = {"name": s.name, "sample": s.sample, "freeze": s.freeze}
    for key in (
        "format",
        "backend",
        "os",
        "capa_version",
        "generated_at_commit",
        "sha256",
    ):
        value = getattr(s, key)
        if value is not None:
            out[key] = value
    return out


def generate_freeze_bytes(
    sample_path: Path,
    *,
    format: Optional[str] = None,
    backend: Optional[str] = None,
    os: Optional[str] = None,
) -> bytes:
    """
    Extract features from `sample_path` and return the freeze byte stream.

    Mirrors the behavior of `python -m capa.features.freeze <sample> <out>` —
    the same entry point a user would invoke to produce snapshots by hand.
    """
    import argparse

    import capa.main
    import capa.features.freeze

    parser = argparse.ArgumentParser()
    capa.main.install_common_args(
        parser, {"input_file", "format", "backend", "os", "signatures"}
    )
    argv = [str(sample_path)]
    if format is not None:
        argv += ["-f", format]
    if backend is not None:
        argv += ["-b", backend]
    if os is not None:
        argv += ["--os", os]
    args = parser.parse_args(args=argv)

    capa.main.handle_common_args(args)
    capa.main.ensure_input_exists_from_cli(args)
    input_format = capa.main.get_input_format_from_cli(args)
    resolved_backend = capa.main.get_backend_from_cli(args, input_format)
    extractor = capa.main.get_extractor_from_cli(args, input_format, resolved_backend)

    return capa.features.freeze.dump(extractor)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
