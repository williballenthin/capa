# feature snapshot fixtures

This directory holds [capa freeze](../../../capa/features/freeze/__init__.py) files that serve
as snapshot fixtures for feature extraction. They're consumed by
[`tests/test_feature_snapshots.py`](../../test_feature_snapshots.py), which regenerates a freeze
from each sample and asserts it matches the committed `.frz` byte-for-byte. Any change that
perturbs what capa extracts (a backend fix, a new feature, a refactor that drops a feature)
shows up as a test failure with a feature-count delta and a truncated unified diff.

Each fixture is produced with `python -m capa.features.freeze --reproducible SAMPLE OUTPUT`.
The `--reproducible` flag zeros out dynamic header metadata (notably the capa version that
is otherwise embedded in the freeze) so fixtures stay stable across capa version bumps —
only changes to extracted features cause test failures.

## layout

- `manifest.json` — JSON list of snapshots (validated by `tests/feature_snapshot_util.py`).
  Each entry has `name`, `sample` (path under `tests/data/`), `freeze` (filename in this
  directory), and a human-written `explanation` describing why the sample was picked. Optional
  `format`/`backend`/`os` overrides are passed through to the freeze CLI.
- `*.frz` — a `capa.features.freeze` byte stream (magic `capa0000` + zlib(utf-8(json(...)))).

## how the sample set was picked

The goal is to exercise every major (format, backend) pair that capa supports with the
smallest reasonable sample, so running the snapshot suite stays under ~1 minute on a laptop
while still catching regressions in every extraction code path. Each fixture's `explanation`
field in `manifest.json` spells out why that specific file is in the set and flags any
candidate for removal.

Backends/formats currently covered:

| fixture          | backend    | format           |
|------------------|------------|------------------|
| `pma01-01-dll`   | viv        | PE 32-bit DLL    |
| `pma16-01-exe`   | viv        | PE 32-bit EXE    |
| `pma21-01-exe`   | viv        | PE 64-bit EXE    |
| `7351f-elf`      | viv        | ELF              |
| `2bf18d-elf`     | viv        | ELF (alternate)  |
| `499c2-sc32`     | viv        | 32-bit shellcode |
| `1c444-dotnet`   | dotnet     | .NET             |

Backends deliberately **not** covered here today (they need external dependencies or
sample material that's not universally available, and can be added later if justified):
BinExport2, IDA idalib, Binary Ninja, and the dynamic sandbox formats (CAPE, DRAKVUF, VMRay).

Big samples like `mimikatz.exe_` and `kernel32.dll_` were tried first but produced multi-MB
freezes that bloat the repository without adding regression-detection value beyond the
smaller PE fixtures.

## regenerating a fixture after an intentional change

```
python -m capa.features.freeze --reproducible \
    tests/data/<sample> tests/fixtures/feature-snapshots/<name>.frz
```

The freeze CLI logs a ready-made manifest entry to its INFO output for easy copy/paste.

## adding a new fixture

1. Add an entry to the `snapshots` list in `manifest.json`. At minimum specify `name`,
   `sample`, `freeze`, and `explanation`. Use `format`/`backend`/`os` only if the defaults
   don't pick the right extractor.
2. Generate the `.frz` file using the command above.
3. Commit both the updated manifest and the new `.frz` file.

## removing a fixture

Read its `explanation` first — some fixtures are deliberately redundant (e.g. a second ELF)
as a belt-and-braces check and explicitly call out that they're the first removal candidate.
Drop the manifest entry and the `.frz` file together.
