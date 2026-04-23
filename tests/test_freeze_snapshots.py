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
Data-driven snapshot tests for capa feature extraction.

For every entry in `tests/fixtures/freezes/manifest.json`, this module
regenerates a freeze from the corresponding sample, compares its sha256
against the committed `.frz` file, and — on mismatch — renders a unified
diff of the freeze contents so a reviewer can see which features appeared,
disappeared, or moved.

To refresh the fixtures after an intentional change, run
`python scripts/generate-freeze-snapshots.py`.
"""

from __future__ import annotations

import json
import zlib
import difflib
from typing import Any

import pytest

import capa.features.freeze
from tests.snapshot_util import Manifest, Snapshot, generate_freeze_bytes, sha256_hex

_MANIFEST = Manifest.load()


def _ids(snapshots: list[Snapshot]) -> list[str]:
    return [s.name for s in snapshots]


def _doc_to_lines(doc: dict[str, Any]) -> list[str]:
    """
    Render a freeze JSON document to a list of lines suitable for unified-diffing.

    We pretty-print the whole document with sorted keys so that field reordering
    (which is meaningful for features) is preserved while key ordering within
    objects is normalized.
    """
    return json.dumps(doc, indent=2, sort_keys=True).splitlines(keepends=True)


def _load_freeze_doc(buf: bytes) -> dict[str, Any]:
    magic = capa.features.freeze.MAGIC
    assert buf[: len(magic)] == magic, "missing freeze magic header"
    return json.loads(zlib.decompress(buf[len(magic) :]).decode("utf-8"))


def _feature_summary(doc: dict[str, Any]) -> dict[str, int]:
    """Counts of features per scope, for a quick at-a-glance delta."""
    features = doc.get("features", {})
    summary: dict[str, int] = {}
    summary["global features"] = len(features.get("global", []))
    summary["file features"] = len(features.get("file", []))

    if doc.get("flavor") == "static":
        functions = features.get("functions", [])

        # The freeze model aliases `basic_blocks` to `basic blocks`; which key the
        # serialized dict uses depends on pydantic's alias generator choice. Normalize.
        def bbs(f: dict[str, Any]) -> list:
            return f.get("basic_blocks") or f.get("basic blocks") or []

        summary["functions"] = len(functions)
        summary["function features"] = sum(
            len(f.get("features", [])) for f in functions
        )
        summary["basic blocks"] = sum(len(bbs(f)) for f in functions)
        summary["basic block features"] = sum(
            len(bb.get("features", [])) for f in functions for bb in bbs(f)
        )
        summary["instructions"] = sum(
            len(bb.get("instructions", [])) for f in functions for bb in bbs(f)
        )
        summary["instruction features"] = sum(
            len(i.get("features", []))
            for f in functions
            for bb in bbs(f)
            for i in bb.get("instructions", [])
        )
    else:
        processes = features.get("processes", [])
        summary["processes"] = len(processes)
        summary["process features"] = sum(len(p.get("features", [])) for p in processes)
        summary["threads"] = sum(len(p.get("threads", [])) for p in processes)
        summary["thread features"] = sum(
            len(t.get("features", [])) for p in processes for t in p.get("threads", [])
        )
        summary["calls"] = sum(
            len(t.get("calls", [])) for p in processes for t in p.get("threads", [])
        )
        summary["call features"] = sum(
            len(c.get("features", []))
            for p in processes
            for t in p.get("threads", [])
            for c in t.get("calls", [])
        )

    return summary


def _format_mismatch(snapshot: Snapshot, expected: bytes, actual: bytes) -> str:
    """Build a failure message describing how the freezes differ."""
    lines = [
        f"freeze snapshot drift for {snapshot.name!r}:",
        f"  sample:         {snapshot.sample}",
        f"  expected freeze: {snapshot.freeze_path} (sha256={sha256_hex(expected)})",
        f"  actual   freeze: <regenerated>     (sha256={sha256_hex(actual)})",
    ]

    expected_doc = _load_freeze_doc(expected)
    actual_doc = _load_freeze_doc(actual)

    exp_summary = _feature_summary(expected_doc)
    act_summary = _feature_summary(actual_doc)
    if exp_summary != act_summary:
        lines.append("")
        lines.append("feature count delta (expected -> actual):")
        keys = sorted(set(exp_summary) | set(act_summary))
        width = max((len(k) for k in keys), default=0)
        for key in keys:
            e = exp_summary.get(key, 0)
            a = act_summary.get(key, 0)
            if e != a:
                lines.append(f"  {key:<{width}s}  {e:6d} -> {a:6d}  ({a - e:+d})")
    else:
        lines.append("")
        lines.append(
            "feature counts match; differences are in feature positions or values."
        )

    diff = list(
        difflib.unified_diff(
            _doc_to_lines(expected_doc),
            _doc_to_lines(actual_doc),
            fromfile=f"expected/{snapshot.freeze}",
            tofile=f"actual/{snapshot.freeze}",
            n=2,
        )
    )

    # Cap the diff so a wholly-changed snapshot doesn't dump thousands of lines
    # into the test output — the feature-count summary above is enough for the
    # common case; run the generator script locally to see the full diff.
    MAX_DIFF_LINES = 200
    lines.append("")
    if len(diff) > MAX_DIFF_LINES:
        lines.append(
            f"unified diff ({len(diff)} lines, truncated to {MAX_DIFF_LINES}):"
        )
        diff = diff[:MAX_DIFF_LINES]
    else:
        lines.append(f"unified diff ({len(diff)} lines):")
    lines.extend(line.rstrip("\n") for line in diff)
    lines.append("")
    lines.append(
        "To refresh fixtures after an intentional change, run:\n"
        "    python scripts/generate-freeze-snapshots.py"
    )
    return "\n".join(lines)


@pytest.mark.parametrize("snapshot", _MANIFEST.snapshots, ids=_ids(_MANIFEST.snapshots))
def test_freeze_snapshot(snapshot: Snapshot):
    """
    Regenerate the freeze for `snapshot.sample` and assert it matches
    `snapshot.freeze` byte-for-byte.
    """
    if not snapshot.sample_path.exists():
        pytest.skip(
            f"sample not present: {snapshot.sample_path} "
            f"(run `git submodule update --init tests/data`)"
        )
    if not snapshot.freeze_path.exists():
        pytest.fail(
            f"snapshot fixture missing: {snapshot.freeze_path} "
            f"(run `python scripts/generate-freeze-snapshots.py`)"
        )

    expected = snapshot.freeze_path.read_bytes()
    actual = generate_freeze_bytes(
        snapshot.sample_path,
        format=snapshot.format,
        backend=snapshot.backend,
        os=snapshot.os,
    )

    if actual == expected:
        return

    pytest.fail(_format_mismatch(snapshot, expected, actual))


def test_manifest_is_consistent():
    """Sanity-check that the manifest doesn't contain duplicates or dangling refs."""
    names = [s.name for s in _MANIFEST.snapshots]
    assert len(names) == len(set(names)), "duplicate snapshot name(s) in manifest"

    freezes = [s.freeze for s in _MANIFEST.snapshots]
    assert len(freezes) == len(set(freezes)), (
        "duplicate freeze file name(s) in manifest"
    )
