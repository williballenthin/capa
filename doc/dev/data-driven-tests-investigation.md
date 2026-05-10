# Data-driven tests: investigation for cross-language portability

This is a survey of the capa test suite that asks: **which tests describe a
core concept of capa that a non-Python implementation must also satisfy, and
how can we move those tests from Python code into language-neutral data
fixtures?**

The motivation is to make capa easier to port to another language (e.g. Rust).
A Rust implementation should be able to consume the same fixtures and
demonstrate that it conforms to the same behavior, without having to translate
44 test files of Python imperative test code.

## Prior art: PR #2986

Upstream PR [mandiant/capa#2986][pr2986] (closes [#2743][issue2743]) already
moves the **feature-presence** tests (the per-backend tests that assert
"backend X extracts feature Y from sample Z at scope S") to a data-driven
fixture format under `tests/fixtures/features/{static,binja-db,binexport,
cape,drakvuf,vmray}.json`. The fixture shape is:

```json
{
  "files": [
    {"key": "mimikatz", "path": "data/mimikatz.exe_", "tags": ["static"]}
  ],
  "features": [
    {
      "file": "mimikatz",
      "location": "function=0x40E5C2",
      "feature": "count(basic blocks): 7"
    },
    {
      "file": "mimikatz",
      "location": "function=0x401000",
      "feature": "characteristic: loop",
      "expected": false
    }
  ]
}
```

Two design choices are worth carrying into the rest of this work:

1. **Features are expressed as strings using the rule-file grammar.** The
   loader uses the same parser the rule engine uses (`parse_feature_string`),
   so adding a new feature kind doesn't require a new schema — it falls out of
   the rule grammar automatically.
2. **Locations encode scope.** A location like `function=0x401000` implies
   function scope; `process=(2176:0),thread=2420,call=2358` implies call
   scope. The scope kind is derived, not declared. Backend selection is by
   tag (`include_tags={"static"}, exclude_tags={"dotnet"}`), not by file.

Everything below follows the same spirit: **express the inputs and outputs as
strings or compact JSON, parse them with whatever parser the engine already
has, and let backends opt in/out by tag.**

[pr2986]: https://github.com/mandiant/capa/pull/2986
[issue2743]: https://github.com/mandiant/capa/issues/2743

---

## Where to put the new fixtures

I propose the following layout, extending what PR #2986 starts:

```
tests/fixtures/
├── features/        # PR #2986 — backend feature extraction
├── engine/          # boolean evaluation of statements over feature dicts
├── matching/        # rule-set matching: rules + features → matched rule names
├── parsing/         # rule YAML → Rule (or InvalidRule)
├── formatting/      # rule YAML → canonicalized YAML
├── optimizer/       # rule statement reordering by cost
├── strings/         # byte buffers → extracted strings
├── rendering/       # feature → display string
├── meta/            # ATT&CK / MBC / MAEC parsing
├── elf/             # ELF bytes → OS / arch / format
├── capabilities/    # full pipeline: extracted features → matched capabilities
├── span-of-calls/   # call sequence → matched rules per scope
├── freeze/          # extractor → freeze JSON → extractor (golden files)
└── proto/           # ResultDocument → proto → ResultDocument (golden files)
```

Each subdirectory has a short `README.md` describing the schema, exactly like
`tests/fixtures/features/README.md`. Each subdirectory's loader is a small
Python module that emits pytest-parameterized cases.

A future Rust implementation reads the same JSON files, runs the same checks,
and reports against the same fixture identifiers. Conformance is then a
percentage of fixtures that pass.

---

## How to read this document

For each candidate, I give:

- **What it tests** — the conceptual behavior under test.
- **Verdict** — GOOD, PARTIAL, POOR, or NEW.
- **Schema** — a concrete JSON sketch.
- **Examples** — one or two real cases lifted from the current test file.
- **Notes** — caveats, alternatives, tradeoffs.

I deliberately offer **multiple format options** at the end (single big
manifest vs. per-case files vs. literate Markdown), since there is no obvious
winner and the choice can be made per-topic.

---

## Tier 1 — pure algorithmic tests (highest value)

These tests describe the **engine semantics**. A new implementation that
passes all of them has implemented the matching engine correctly. They have
no binary, file system, or extractor dependency.

### 1. `test_engine.py` — boolean evaluation (GOOD)

Tests that `And`, `Or`, `Not`, `Some`, `Range` over a feature dictionary
evaluate to the right boolean. Currently 9 hand-written tests, ~50 cases.

**Schema** (`tests/fixtures/engine/eval.json`):

```json
{
  "cases": [
    {
      "name": "and: both present",
      "statement": {"and": ["number: 1", "number: 2"]},
      "features": {"number: 1": ["0x401001"], "number: 2": ["0x401002"]},
      "expected": true
    },
    {
      "name": "range: bounded, exact 2",
      "statement": "count(number(1)): 2",
      "features": {"number: 1": ["0x401001", "0x401002"]},
      "expected": true
    },
    {
      "name": "short-circuit: only first satisfied child captured",
      "statement": {"or": ["number: 1", "number: 2"]},
      "features": {"number: 1": ["0x401001"]},
      "expected": true,
      "result": {"children_count": 1}
    }
  ]
}
```

Notes:
- **Statements** use either a feature string (single feature) or a single-key
  object whose value is a list (`and`, `or`, `not`, `N or more`). This is the
  same shape the rule YAML parser already understands; we can literally pass
  it through `parse_features` or convert and use the rule engine.
- **Locations** are hex strings; type is `AbsoluteVirtualAddress` by default.
  Use `{"type": "process", "pid": 1234, "ppid": 0}` only when something other
  than the default is needed (e.g., dynamic addresses).
- **Optional `result` block** captures the additional structural assertions
  in `test_short_circuit` and `test_eval_order` (children count, child
  ordering). Most cases won't need it.

This single fixture replaces ~150 lines of imperative test code and codifies
the engine's contract.

### 2. `test_match.py` — rule-set matching (GOOD)

Tests that a rule + features → a set of matched rule names + matched-rule
feature additions (`MatchedRule("foo")`, namespace propagation). 23 tests.

**Schema** (`tests/fixtures/matching/cases.json`):

```json
{
  "cases": [
    {
      "name": "simple match adds matched-rule features",
      "scope": "function",
      "rules": [
        "rule:\n  meta:\n    name: test rule\n    namespace: testns1/testns2\n    scopes: {static: function, dynamic: process}\n  features:\n    - number: 100\n"
      ],
      "features": {"number: 100": ["0x1", "0x2"]},
      "expect_matched_rules": ["test rule"],
      "expect_matched_rule_features": [
        "match: test rule",
        "match: testns1",
        "match: testns1/testns2"
      ]
    },
    {
      "name": "regex with implied wildcards",
      "scope": "function",
      "rules": [{"$ref": "rules/regex-bbbb.yml"}],
      "features": {"string: \"abbbba\"": ["0x1"]},
      "expect_matched_rules": ["rule with implied wildcards"]
    }
  ]
}
```

Notes:
- **Rules can be inline strings or `$ref`-loaded YAML files.** Inline keeps
  small cases readable; `$ref` keeps multi-rule cases tidy. Sibling rule
  files live under `tests/fixtures/matching/rules/`.
- **`expect_matched_rule_features`** captures the namespace-propagation
  behavior tested in `test_match_namespace`.
- The `_RuleFeatureIndex` tests at the end of `test_match.py`
  (`test_index_features_*_unstable`) are explicitly marked unstable and
  inspect Python-internal data structures. They should stay as Python tests.

### 3. `test_rules.py` (parsing subset) — rule YAML grammar (GOOD)

About 35 of the 44 tests in this file are "parse this YAML and assert the
result is well-formed (or that it raises `InvalidRule`)." The parser is a
language-neutral concept; the tests are perfect data-driven candidates.

**Schema** (`tests/fixtures/parsing/cases.json`):

```json
{
  "valid": [
    {
      "name": "number with symbol description",
      "yaml": "rule:\n  meta: {...}\n  features:\n    - number: 0x100 = symbol name\n",
      "expect": {
        "scopes": {"static": "function", "dynamic": "process"},
        "feature_count": 1,
        "first_feature": "number: 0x100",
        "first_feature_description": "symbol name"
      }
    }
  ],
  "invalid": [
    {
      "name": "feature unknown to grammar",
      "yaml": "rule:\n  meta: {...}\n  features:\n    - foo: true\n",
      "expect_error": "InvalidRule"
    },
    {
      "name": "characteristic at file scope is invalid",
      "yaml": "rule:\n  meta: {static: file, dynamic: process}\n  features:\n    - characteristic: nzxor\n",
      "expect_error": "InvalidRule"
    }
  ]
}
```

Notes:
- **Error kinds.** Just `InvalidRule` is fine for now; capa doesn't currently
  distinguish error subtypes. If the codebase grows error tags, the schema
  can carry them in `expect_error.reason`.
- **`expect` shape** is a small, flat assertion grammar: scope kinds, feature
  count at top level, top-level descriptions. Tests that traverse the rule
  tree (e.g., `test_rule_descriptions` recursing through nested
  statements) are best left in Python — or expressed via a richer "expect"
  using a JSON-Path-like selector (`statement.children[0].description`).
- **Sub-files.** `test_rules_insn_scope.py` (12 tests) is essentially the
  same shape with the addition of an `expected_rule_set_shape` block:
  `{"function_rules": 1, "instruction_rules": 1}`.

### 4. `test_optimizer.py` — rule statement reordering (GOOD)

One test: load a rule, snapshot the order of children, run the optimizer,
snapshot again. The optimizer is pure logic; this is trivially data-driven.

**Schema** (`tests/fixtures/optimizer/cases.json`):

```json
{
  "cases": [
    {
      "name": "and: cheap features bubble up",
      "rule_yaml": "rule: ...\n  features:\n    - and:\n        - substring: foo\n        - arch: amd64\n        - mnemonic: cmp\n        - and: [...]\n        - or: [...]\n",
      "before": ["substring", "arch", "mnemonic", "and", "or"],
      "after":  ["arch", "mnemonic", "substring", "or", "and"]
    }
  ]
}
```

Notes:
- The "shape" assertion is just a list of feature/statement type names in
  order. It directly mirrors the existing assertions (`isinstance(children[0],
  Arch)`).

### 5. `test_fmt.py` — rule YAML canonicalization (GOOD)

5 tests: feed in a messy YAML rule, assert that `Rule.from_yaml(src).to_yaml()
== EXPECTED`. A pure round-trip.

**Schema** (`tests/fixtures/formatting/cases.json`):

```json
{
  "cases": [
    {
      "name": "top-level elements reordered",
      "input":    "tests/fixtures/formatting/inputs/top-level-reorder.yml",
      "expected": "tests/fixtures/formatting/expected/canonical.yml"
    }
  ]
}
```

Notes:
- Use sidecar `.yml` files instead of inline strings; YAML embedded as JSON
  string is painful to read and edit.
- The `EXPECTED` block in `test_fmt.py` is the same for several inputs — the
  schema naturally factors that out.

### 6. `test_strings.py` — byte buffer string extraction (GOOD)

4 tests over `extract_ascii_strings`, `extract_unicode_strings`,
`buf_filled_with`, `is_printable_str`. Pure functions, byte input, structured
output.

**Schema** (`tests/fixtures/strings/cases.json`):

```json
{
  "extract_ascii": [
    {"name": "two strings", "buf_hex": "48656c6c6f20576f726c640054686973...", "min_length": 4, "expected": [{"s": "Hello World", "off": 0}, {"s": "This is a test", "off": 12}]},
    {"name": "non-ascii cuts string", "buf_hex": "48656c6c6fff576f726c6400", "min_length": 4, "expected": [{"s": "Hello", "off": 0}, {"s": "World", "off": 6}]}
  ],
  "extract_unicode": [...],
  "buf_filled_with": [
    {"buf_hex": "0000000000000000", "byte": 0, "expected": true},
    {"buf_hex": "00010001000100010001000100010001", "byte": 0, "expected": false}
  ],
  "is_printable_str": [
    {"s": "Hello World", "expected": true},
    {"s": " ", "expected": false}
  ]
}
```

Notes:
- `buf_hex` keeps non-printable bytes in JSON. Alternative: base64.
- This test family is small enough that a single file is fine; no need to
  shard.

---

## Tier 2 — format-tied tests that can still be expressed as data

These tests assert capa's wire formats: rendering, the freeze format, the
proto format, the result document. A non-Python implementation must produce
the same outputs, so codifying them as golden files is valuable, but the
format is still capa-specific (not a "core algorithm").

### 7. `test_render.py` — feature rendering (GOOD)

`test_render_vverbose_feature` is already parameterized inline. 23 cases.
`test_render_meta_attack` / `test_render_meta_mbc` / `test_render_meta_maec`
are pure string-parsing tests (parse `"Tactic::Technique::Subtechnique
[T1234]"` → structured fields).

**Schema** (`tests/fixtures/rendering/cases.json`):

```json
{
  "feature_vverbose": [
    {"feature": "os: windows", "expected": "os: windows"},
    {"feature": "string: foo", "address": "0x401000", "expected": "string: \"foo\" @ 0x401000"},
    {"feature": "operand[0].number: 0xC", "address": "0x401000", "expected": "operand[0].number: 0xC @ 0x401000"}
  ],
  "attack_meta": [
    {
      "input": "Persistence::Create or Modify System Process::Windows Service [T1543.003]",
      "expected": {
        "id": "T1543.003",
        "tactic": "Persistence",
        "technique": "Create or Modify System Process",
        "subtechnique": "Windows Service"
      }
    }
  ],
  "mbc_meta": [
    {
      "input": "Defense Evasion::Disable or Evade Security Tools::Heavens Gate [F0004.008]",
      "expected": {
        "id": "F0004.008",
        "objective": "Defense Evasion",
        "behavior": "Disable or Evade Security Tools",
        "method": "Heavens Gate"
      }
    }
  ]
}
```

Notes:
- The vverbose rendering happens to match the rule-grammar form for most
  features. So feature parsing + feature rendering is approximately a
  round-trip — and that's a useful spec property to codify.
- `test_render_meta_maec` constructs a `Mock(spec=ResultDocument)` and checks
  output substrings; that test is genuinely Python-specific. Skip it.

### 8. `test_result_document.py` — engine AST → rdoc node mapping (PARTIAL)

20+ tests, each: build a tiny engine node, call `node_from_capa`, assert the
result has the right capa-rdoc node type. This is mechanical structural
mapping; mostly tedious to write in Python.

**Schema** (`tests/fixtures/result-document/node-mapping.json`):

```json
{
  "cases": [
    {"input": {"some": {"min": 0, "of": []}}, "expected_rdoc": "OptionalStatement"},
    {"input": {"some": {"min": 1, "of": ["number: 0"]}}, "expected_rdoc": "SomeStatement"},
    {"input": {"range": {"of": "number: 0"}}, "expected_rdoc": "RangeStatement"},
    {"input": {"and": ["number: 0"]}, "expected_rdoc": "CompoundStatement", "expected_type": "AND"},
    {"input": "os: windows", "expected_rdoc": "FeatureNode", "expected_feature_type": "OSFeature"}
  ]
}
```

Notes:
- The "expected" side names a Python class. For cross-language portability,
  rename these to **canonical kind strings** (`statement.optional`,
  `statement.compound.and`, `feature.os`) and have both Python and Rust
  implement a `kind()` method. That makes the assertions language-neutral.
- Doing this is also a small alignment improvement: the fixtures become a
  *spec* for the result-document grammar, not just a Python class checker.

### 9. `test_freeze_static.py` / `test_freeze_dynamic.py` — freeze format (PARTIAL)

These tests build a `NullStaticFeatureExtractor` from in-memory data and
round-trip it through the freeze format. The in-memory data is itself
data-driven in spirit, just expressed in Python.

**Schema** (`tests/fixtures/freeze/static.json`):

```json
{
  "extractors": [
    {
      "name": "minimal-xor-loop",
      "base_address": "0x401000",
      "sample_hashes": {"md5": "...", "sha1": "...", "sha256": "..."},
      "file_features": [
        {"address": "0x402345", "feature": "characteristic: embedded pe"}
      ],
      "functions": [
        {
          "address": "0x401000",
          "features": [{"address": "0x401000", "feature": "characteristic: indirect call"}],
          "basic_blocks": [
            {
              "address": "0x401000",
              "features": [{"address": "0x401000", "feature": "characteristic: tight loop"}],
              "instructions": [
                {"address": "0x401000", "features": ["mnemonic: xor", "characteristic: nzxor"]},
                {"address": "0x401002", "features": ["mnemonic: mov"]}
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

Notes:
- A loader builds the `NullStaticFeatureExtractor` from this JSON, then runs
  the existing `test_freeze_str_roundtrip` / `test_freeze_bytes_roundtrip` /
  `compare_extractors` checks against it.
- This same JSON shape is *also* the input for the capabilities tests
  below — fixtures compose well.

### 10. `test_proto.py` — proto round-trip (POOR)

The proto tests load a `ResultDocument` from a Python fixture, convert to
proto, and compare every field. The conversion logic is largely mechanical
field copying. A better data-driven model is **golden-file conformance**: a
small set of known `ResultDocument` JSON files plus their expected
proto-as-JSON serialization.

**Schema** (`tests/fixtures/proto/cases.json`):

```json
{
  "cases": [
    {
      "name": "pma01-01",
      "rdoc_path": "tests/fixtures/proto/inputs/pma01-01.rdoc.json",
      "proto_json_path": "tests/fixtures/proto/expected/pma01-01.pb.json"
    }
  ]
}
```

Notes:
- The proto schema lives in `capa/render/proto/capa.proto` — that's the
  language-neutral spec. Golden files are language-neutral too. The actual
  Python tests (`test_addr_to_pb2` etc.) that check field-by-field mappings
  are best left as Python because they exercise the protobuf API directly.

---

## Tier 3 — interesting new opportunities

These are tests where a data-driven format would let us test capa's
behavior **without** real binaries — either because we can capture the
extractor output as data, or because the test is really about a small
algorithm that operates on a known input shape.

### 11. `test_capabilities.py` — end-to-end on a real extractor (NEW)

Currently uses `z9324d_extractor`, which loads `9324d1a8...` via vivisect and
takes seconds. The test is really: "given these features at these addresses,
do these rules fire?"

**Idea: capture the extractor output as a freeze JSON, then matching becomes
data-driven.** The freeze format is exactly that — a snapshot of all
extracted features per scope. We can use `tests/fixtures/freeze/*.json` as
inputs, attach a rule set, and check matched rule names.

**Schema** (`tests/fixtures/capabilities/cases.json`):

```json
{
  "cases": [
    {
      "name": "match across scopes (file + function)",
      "extractor": "tests/fixtures/freeze/9324d1a8.frz.json",
      "rules": ["tests/fixtures/capabilities/rules/install-service.yml",
                "tests/fixtures/capabilities/rules/text-section.yml",
                "tests/fixtures/capabilities/rules/text-section-and-install-service.yml"],
      "expect_matched": ["install service", ".text section",
                         ".text section and install service"]
    },
    {
      "name": "byte matching on real bytes",
      "extractor": "tests/fixtures/freeze/9324d1a8.frz.json",
      "rules_inline": [
        "rule:\n  meta: {...}\n  features:\n    - bytes: ED 24 9E F4 52 A9 07 47 ...\n"
      ],
      "expect_matched": ["byte match test"]
    }
  ]
}
```

Notes:
- **The freeze JSON is generated once** (offline, by the Python implementation
  on the real binary) and committed. From then on the test is hermetic.
  That's a significant maintenance win.
- This unlocks the same trick for the dynamic span-of-calls and call-scope
  tests below.
- For a Rust port: the Rust matcher reads the freeze JSON the same way and
  is expected to produce the same matched-rules set. This is one of the
  highest-value conformance tests.

### 12. `test_dynamic_span_of_calls_scope.py` — span semantics (NEW)

The test is currently long because it loads a real CAPE report and threads.
But the *semantics* — the rule scope `dynamic: span of calls`, what counts
as "in scope," how span windows slide — are independent of how the calls
were captured.

**Schema** (`tests/fixtures/span-of-calls/cases.json`):

```json
{
  "cases": [
    {
      "name": "match at first call",
      "calls": [
        {"id": 8,  "api": "GetSystemTimeAsFileTime"},
        {"id": 9,  "api": "GetSystemInfo"},
        {"id": 10, "api": "LdrGetDllHandle", "args": [1974337536, "kernel32.dll"]},
        {"id": 11, "api": "LdrGetProcedureAddress", "args": [..., "AddVectoredExceptionHandler", ...]}
      ],
      "rule": "rule:\n  meta: {dynamic: call}\n  features:\n    - api: GetSystemTimeAsFileTime\n",
      "expect_match_at_call_ids": [8]
    },
    {
      "name": "match at first span window of size 4",
      "calls": [...],
      "rule": "rule:\n  meta: {dynamic: span of calls}\n  features:\n    - and:\n        - api: AddVectoredExceptionHandler\n        - api: RemoveVectoredExceptionHandler\n",
      "expect_match_at_span_call_ids": [...]
    }
  ]
}
```

Notes:
- A small test-only loader builds a synthetic `DynamicFeatureExtractor` from
  the call list. We don't need a full CAPE report; we need only what the
  scope test exercises.
- This effectively replaces the comments in the current test file
  (lines 15-32 of `test_dynamic_span_of_calls_scope.py`), which already
  describe the input as a list of calls.

### 13. `test_os_detection.py` — ELF OS heuristic (PARTIAL)

Tests like `test_elf_sh_notes` open a real ELF file and assert
`detect_elf_os(f) == "linux"`. The interesting input isn't the binary, it's
which detection signals fire (osabi, ph notes, sh notes, linker, symtab,
needed-deps). The current test docstrings already enumerate the signals.

Two options:

**Option A — keep the binary input, just declare it.**

```json
{
  "cases": [
    {"name": "elf_sh_notes", "path": "data/2f7f5f...", "expected_os": "linux",
     "expected_signals": {"sh_notes": "linux"}}
  ]
}
```

**Option B — make the test signal-driven.** Refactor `detect_elf_os` to
expose its per-signal results, and have the test fixture *capture* those
signals. Now you can have a fixture that says "given these signal results,
the heuristic should pick OS X" — entirely portable, no binary required.

```json
{
  "cases": [
    {"name": "two-signal hurd",
     "signals": {"osabi": null, "ph_notes": null, "sh_notes": "hurd",
                 "linker": null, "abi_versions": "hurd",
                 "symtab": null, "needed_deps": "hurd"},
     "expected_os": "hurd"}
  ]
}
```

Option B is the prize: it tests the heuristic logic without depending on
binaries at all, and the heuristic is the genuinely interesting part. The
binary tests can shrink to a handful of integration smoke tests.

### 14. `test_helpers.py::test_generate_symbols` — symbol expansion (GOOD)

`generate_symbols("kernel32", "CreateFileA", include_dll=True)` →
`["kernel32.CreateFileA", "kernel32.CreateFile", "CreateFileA", "CreateFile"]`.
A pure function from `(dll, name, include_dll)` to a set of symbols, with
A/W de-suffixing rules. Trivially data-driven.

```json
{
  "cases": [
    {"dll": "kernel32", "name": "CreateFileA", "include_dll": true,
     "expected": ["kernel32.CreateFileA", "kernel32.CreateFile", "CreateFileA", "CreateFile"]},
    {"dll": "ws2_32", "name": "#1", "include_dll": true,
     "expected": ["ws2_32.#1"]}
  ]
}
```

### 15. `test_extractor_hashing.py` — sample hashing (POOR-as-pure-data, GOOD-as-conformance)

It's just `MD5/SHA1/SHA256` of the file. The hash logic is library code; we
don't need to test that. What we *do* want to assert is "every backend
extractor reports the same hashes for the same sample" — a conformance
property.

```json
{
  "cases": [
    {"file": "mimikatz",
     "expected": {"md5": "...", "sha1": "...", "sha256": "..."},
     "applies_to": ["viv", "pefile", "binja", "ida", "ghidra", "binexport", "freeze"]}
  ]
}
```

This is small and natural. One fixture, every backend that loads the file
asserts the same triple. (And it's basically already free if we extend the
existing `tests/fixtures/features/static.json` `files` table with optional
expected-hash fields.)

### 16. `test_function_id.py` — FLIRT-style matching (PARTIAL)

This tests that capa correctly identifies library functions in a binary via
embedded `.pat` signatures. The matching logic is a pure algorithm operating
on function bytes + a `.pat` database. It can be expressed as:

```json
{
  "cases": [
    {"function_bytes_hex": "55 8B EC ...",
     "pat_db": "tests/fixtures/function-id/test_aullrem.pat",
     "expected_match": "__aullrem"}
  ]
}
```

But honestly, this is small (4 tests) and the binary input is intrinsic. I'd
leave it as Python and only re-implement the FLIRT-matching test in Rust if
function ID becomes a port goal. NEW pri: low.

### 17. `test_drakvuf_models.py` / `test_cape_model.py` / `test_vmray_model.py` — model parsing (GOOD)

These are JSON/XML deserialization round-trips. Already mostly data; the
test just calls `Model(**json_dict)` and asserts on fields.

For `test_drakvuf_models.py`, the JSON fixture *is the test*. Just commit the
JSON snippets and the expected parsed-field map:

```json
{
  "cases": [
    {
      "input_path": "tests/fixtures/drakvuf-model/syscall-NtRemoveIoCompletionEx.json",
      "expected_fields": {
        "method": "NtRemoveIoCompletionEx",
        "nargs": 6,
        "arguments": {"IoCompletionHandle": "0xffffffff80001ac0", "...": "..."}
      }
    }
  ]
}
```

For VMRay, it gets harder — the model parses XML — but the principle is the
same. The big VMRay/CAPE report files (`tests/data/dynamic/...`) are already
the "fixtures"; the tests just need a clearer schema describing what fields
to assert.

---

## Tier 4 — leave as Python

These tests genuinely depend on Python-specific behavior or system
integration, and gain little from data-driven conversion:

- `test_main.py`, `test_scripts.py` — CLI integration. Subprocess + exit
  codes. Not portable, and not interesting from a port-conformance point of
  view (a Rust port has its own CLI).
- `test_rule_cache.py` — capa's pickle/zlib cache for compiled rule sets. A
  Rust port would have its own caching strategy, if any.
- `test_helpers.py::test_is_dev_environment` — checks Python file system
  layout. Trivial, ignore.
- `test_binexport_accessors.py` — pattern-matching on BinExport2 protobuf
  instructions. Half data-driven (the patterns are strings) but tightly
  coupled to the protobuf API. Could potentially be ported in a separate
  pass; not high priority.

---

## Format options

PR #2986 chose **JSON, one big manifest per category**. That's a sensible
default but not the only choice. For each category above, the choice can be
made independently.

### Option A — single big JSON manifest per category (PR #2986's choice)

`tests/fixtures/engine/eval.json`, `tests/fixtures/matching/cases.json`, etc.

Pros: one file to grep, easy to count cases, easy diffs.

Cons: large diffs hide individual case changes; merge conflicts when many
contributors touch the same file; YAML-inside-JSON-strings is ugly.

### Option B — one file per case

`tests/fixtures/matching/cases/match-simple.json`,
`tests/fixtures/matching/cases/match-namespace.json`, ...

Pros: clean diffs, no merge conflicts, you can give each case a real name in
the file system.

Cons: more files; you need a `glob()` loader.

### Option C — manifest + sidecar files (recommended hybrid)

Tiny manifest (`cases.json`) lists test cases by name, with metadata; rule
YAML and expected outputs live in sidecar `.yml` / `.txt` files referenced by
path. PR #2986 already does this pattern for sample binaries.

Pros: case metadata in JSON (easy to filter, tag, mark `xfail`); large
multiline content (rules, expected canonical YAML) in their native format.

Cons: two files per case; minor indirection.

I recommend **C for `formatting/`, `matching/` (multi-rule cases),
`freeze/`, `capabilities/`, `proto/`**, and **A for `engine/`,
`strings/`, `optimizer/`, `rendering/`, `meta/`, `helpers/`** — basically:
"if a case fits on a screen, put it inline; otherwise sidecar."

### Option D — literate Markdown

Put each case in a Markdown file with code blocks:

````markdown
# match-simple

## rule
```yaml
rule:
  meta:
    name: test rule
    ...
  features:
    - number: 100
```

## features
```json
{"number: 100": ["0x1", "0x2"]}
```

## expect
matched_rules: [test rule]
matched_rule_features: [match: test rule, match: testns1, match: testns1/testns2]
````

Pros: readable as documentation; doubles as a tutorial; great for a
"specification by example" feel.

Cons: needs a custom parser; harder to auto-load; inconvenient for many
cases.

I'd reserve this for a **`docs/spec/` companion** — extract a few canonical
cases per topic and present them as the readable spec, separate from the
exhaustive machine-readable fixtures. This pairs well with the porting goal
because the spec doc is the human-facing reference; the JSON fixtures are
the machine-facing conformance suite.

### Option E — TOML

Same shape as JSON, slightly nicer for hand-editing. Rust ecosystem loves
TOML. But Python's stdlib `tomllib` is read-only and inline JSON inside
TOML strings remains awkward. Not worth diverging from JSON for.

---

## Cross-cutting concerns

### Shared feature parser

Every category above leans on the rule grammar's feature parser
(`parse_features`, `parse_feature_string`). PR #2986 already extracts the
helpers needed to build a `Feature` or a `Range` (count) from a string. **A
Rust port needs the same parser.** That parser is therefore a key artifact:
once it works in Rust, it unlocks roughly 60% of the data-driven tests
proposed here.

### Shared scope inference

PR #2986 derives scope from the location string (`function=0x...`,
`process=(...)`, `call=...`). The grammar of these locations is small but
should be documented as part of the spec. Engine and capabilities tests
reuse the same grammar.

### Tagging for backend selection

PR #2986 tags fixtures with `dotnet`, `elf`, `dynamic`, `flirt`, etc. The
same tag system extends naturally to engine/matching tests when they
touch backend-specific behavior (e.g., `os: windows` vs. `os: linux` test
cases). Backends opt in/out by tag; new backends declare their policy
without editing every fixture.

### Marks for known bugs

PR #2986 supports per-case `marks` with `{backend, mark, reason}` so a
backend that has a known bug can `skip` or `xfail` the case without removing
it. We should adopt the same convention everywhere; it's the difference
between "we deleted that test" and "Python capa has a known issue with
embedded PEs at absolute offsets" (an honest, persisting record).

### Conformance reporting

A future Rust port can implement a runner that loads the fixture JSONs and
reports `passed/failed/xfailed/skipped` per category. Treat this as the
porting acceptance test. It's also useful for the existing Python suite —
makes it easy to answer "how much of the engine spec do we have coverage
for?"

---

## Roadmap (suggested)

I'd order this by independence + value:

1. **Land PR #2986.** Everything below builds on its parser and scope
   helpers.
2. **`tests/fixtures/engine/`** (Tier 1, #1). Smallest scope, biggest
   conceptual win — the engine semantics in 1-2 JSON files.
3. **`tests/fixtures/strings/`** (Tier 1, #6). One file, one afternoon.
   Useful even before any port.
4. **`tests/fixtures/matching/`** (Tier 1, #2). Builds on #1 + the
   feature parser.
5. **`tests/fixtures/parsing/`** (Tier 1, #3). Mostly a mechanical port of
   `test_rules.py`; will surface a few rule-validation edges that are
   currently asserted only via Python exceptions.
6. **`tests/fixtures/optimizer/`, `formatting/`, `rendering/`, `meta/`**
   (Tier 1 + 2). Small, useful, all benefit from the rule parser already
   in place.
7. **`tests/fixtures/freeze/`** as a *building block*. Defines a JSON shape
   for an in-memory extractor.
8. **`tests/fixtures/capabilities/`** (#11) on top of `freeze/`. This is the
   payoff: a full pipeline test that doesn't need a real binary.
9. **`tests/fixtures/span-of-calls/`** (#12). Same trick for dynamic.
10. **`tests/fixtures/elf/`** Option B (#13). Refactor `detect_elf_os` so the
    heuristic is testable without binaries; keep a minimal binary smoke test.
11. **Hash-conformance** (#15) is a cheap addition to the existing fixture
    files.
12. Everything else as opportunities arise.

After steps 1-8, a Rust port has enough conformance fixtures to claim
"matching engine compatibility": parser, evaluator, matcher, optimizer,
renderer, and one full pipeline test. That is, IMO, the right scope to aim
for first.

---

## Open questions

- **Address representation in JSON.** Hex strings (`"0x401000"`) are most
  ergonomic. But for dynamic addresses (`process=(2176:0),thread=2420,call=
  2358`), the location grammar is more involved. Worth documenting once.
- **Statement representation.** Inline strings (`"and: [...]"`) are short
  but require a sub-parser; nested objects (`{"and": [...]}`) are explicit
  but verbose. PR #2986 uses inline strings via the rule grammar. I'd stay
  consistent.
- **Test selection in Rust.** Should the Rust port read pytest marks
  (`xfail`, `skip`) or use its own runner? I'd argue for the latter — the
  fixture JSON declares the *expected behavior*; the runner is whatever the
  language wants. The `marks` field lets each runner decide locally what to
  do with a known bug.
- **Where do the larger golden files live?** `tests/data/` is currently
  managed via a submodule (`capa-testfiles`). Big freeze snapshots and
  proto goldens probably belong there too, not in the main tree.

---

## TL;DR

**Place:** `tests/fixtures/<category>/`, mirroring the structure PR #2986
introduces for `features/`.

**Tier 1 (highest value, do first):** engine, matching, parsing, optimizer,
formatting, strings — all pure logic, all small, together they define the
*matching engine specification* a port must satisfy.

**Tier 2 (capa wire formats):** rendering, result-document mapping, freeze
roundtrip, proto roundtrip — codify capa's output shapes as goldens.

**Tier 3 (creative):** treat the freeze JSON as the universal extractor
representation. With it, end-to-end capability matching, dynamic span
matching, and OS detection can all become hermetic, binary-free, and
language-neutral tests.

**Tier 4 (leave alone):** CLI smoke tests, rule cache, scripts.

**Format:** JSON manifest per category, with sidecar files for content >1
screen. Reuse PR #2986's feature parser, scope inference, tags, and marks
conventions verbatim.
