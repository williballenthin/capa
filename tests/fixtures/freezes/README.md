# freeze snapshot fixtures

This directory contains [capa freeze](../../../capa/features/freeze/__init__.py) files that
serve as snapshot fixtures for feature extraction. They're used by
`tests/test_freeze_snapshots.py` to detect unexpected changes to the features that capa
extracts from a curated set of sample binaries.

Each snapshot is produced by running feature extraction against a sample in the
[capa-testfiles](https://github.com/mandiant/capa-testfiles) submodule and then serializing
the result with `capa.features.freeze.dump`. Because the freeze is deterministic, each run
against the same sample should produce identical bytes; a mismatch between the committed
snapshot and a freshly regenerated one indicates that feature extraction has changed.

## layout

- `manifest.json` — list of snapshots plus metadata (sample path, backend override, capa version,
  commit used to generate, sha256 of the freeze file).
- `*.frz` — a `capa.features.freeze` byte stream (magic `capa0000` + zlib(utf-8(json(...)))).

## regenerating

Call `python scripts/generate-freeze-snapshots.py` from the repository root. This refreshes every
snapshot and rewrites `manifest.json` with the current capa version and commit hash. Pass
`--only NAME ...` to limit the update to specific entries. The samples must be present in the
`tests/data/` submodule.

## adding a new fixture

1. Append an entry to the `snapshots` list in `manifest.json`. At minimum specify `name`,
   `sample`, and `freeze`.
2. Run `python scripts/generate-freeze-snapshots.py --only NAME` to generate the `.frz` file
   and fill in `capa_version`, `generated_at_commit`, and `sha256`.
3. Commit both the updated manifest and the new `.frz` file.
