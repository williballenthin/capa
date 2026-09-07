# Copyright 2023 Google LLC
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

import io
import struct
from pathlib import Path

import fixtures
from elftools.elf.dynamic import DynamicSegment
from elftools.elf.elffile import ELFFile

from capa.features.extractors.elffile import (
    extract_file_export_names,
    extract_file_import_names,
    extract_file_section_names,
)

SAMPLE_PATH = fixtures.CD / "data" / "055da8e6ccfe5a9380231ea04b850e18.elf_"
STRIPPED_SAMPLE_PATH = fixtures.CD / "data" / "bb38149ff4b5c95722b83f24ca27a42b.elf_"


def check_import_features(sample_path, expected_imports):
    path = Path(sample_path)
    elf = ELFFile(io.BytesIO(path.read_bytes()))
    # Extract imports
    imports = list(extract_file_import_names(elf))

    # Verify that at least one import was found
    assert len(imports) > 0, "No imports were found."

    # Extract the symbol names from the extracted imports
    extracted_symbol_names = [imported[0].value for imported in imports]

    # Check if all expected symbol names are found
    for symbol_name in expected_imports:
        assert symbol_name in extracted_symbol_names, f"Symbol '{symbol_name}' not found in imports."


def check_export_features(sample_path, expected_exports):
    path = Path(sample_path)
    elf = ELFFile(io.BytesIO(path.read_bytes()))
    # Extract imports
    exports = list(extract_file_export_names(elf))

    # Verify that at least one export was found
    assert len(exports) > 0, "No exports were found."

    # Extract the symbol names from the extracted imports
    extracted_symbol_names = [exported[0].value for exported in exports]

    # Check if all expected symbol names are found
    for symbol_name in expected_exports:
        assert symbol_name in extracted_symbol_names, f"Symbol '{symbol_name}' not found in exports."


def test_stripped_elffile_import_features():
    expected_imports = ["__cxa_atexit", "__cxa_finalize", "__stack_chk_fail", "fclose", "fopen", "__android_log_print"]
    check_import_features(STRIPPED_SAMPLE_PATH, expected_imports)


def test_stripped_elffile_export_features():
    expected_exports = [
        "_ZN7_JNIEnv14GetArrayLengthEP7_jarray",
        "Java_o_ac_a",
        "Java_o_ac_b",
        "_Z6existsPKc",
        "_ZN7_JNIEnv17GetStringUTFCharsEP8_jstringPh",
        "_ZN7_JNIEnv21GetObjectArrayElementEP13_jobjectArrayi",
        "_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc",
    ]
    check_export_features(STRIPPED_SAMPLE_PATH, expected_exports)


def test_elffile_import_features():
    expected_imports = [
        "memfrob",
        "puts",
        "__libc_start_main",
        "malloc",
        "__cxa_finalize",
    ]
    check_import_features(SAMPLE_PATH, expected_imports)


def test_elffile_export_features():
    expected_exports = [
        "deregister_tm_clones",
        "register_tm_clones",
        "__do_global_dtors_aux",
        "completed.8060",
        "__do_global_dtors_aux_fini_array_entry",
        "frame_dummy",
        "_init",
        "__libc_csu_fini",
        "_fini",
        "__dso_handle",
        "_IO_stdin_used",
        "__libc_csu_init",
    ]
    check_export_features(SAMPLE_PATH, expected_exports)


def remove_section(buf: bytes, name: str) -> bytes:
    """
    zero the bytes of the named section, like `strip --remove-section=<name>` does.

    an SHF_ALLOC section sits inside a PT_LOAD, so strip can't excise it without
    shifting virtual addresses: it drops the section header and zero-fills the
    bytes in place, leaving any dynamic tag that points there with its original
    value.
    """
    elf = ELFFile(io.BytesIO(buf))

    section = elf.get_section_by_name(name)
    assert section is not None, f"sample has no {name} section"

    b = bytearray(buf)
    b[section["sh_offset"] : section["sh_offset"] + section["sh_size"]] = b"\x00" * section["sh_size"]

    # drop the section header, too, by pointing it at the null section
    shdr_offset = elf["e_shoff"] + elf.get_section_index(name) * elf["e_shentsize"]
    b[shdr_offset : shdr_offset + elf["e_shentsize"]] = b"\x00" * elf["e_shentsize"]

    return bytes(b)


def remove_section_headers(buf: bytes) -> bytes:
    """zero e_shoff/e_shnum/e_shstrndx, like a super-stripped binary that has no section headers"""
    elf = ELFFile(io.BytesIO(buf))
    assert elf.elfclass == 64, "only implemented for ELF64"

    b = bytearray(buf)
    # Elf64_Ehdr: e_shoff at 0x28, e_shnum at 0x3c, e_shstrndx at 0x3e
    b[0x28:0x30] = b"\x00" * 8
    b[0x3C:0x40] = b"\x00" * 4

    return bytes(b)


def zero_dynamic_table(buf: bytes, tag: str, size: int) -> bytes:
    """zero-fill the head of the table the given dynamic tag points at, leaving the tag in place"""
    elf = ELFFile(io.BytesIO(buf))

    for segment in elf.iter_segments():
        if not isinstance(segment, DynamicSegment):
            continue

        _, offset = segment.get_table_offset(tag)
        if offset is None:
            continue

        b = bytearray(buf)
        b[offset : offset + size] = b"\x00" * size
        return bytes(b)

    raise AssertionError(f"sample has no {tag}")


def get_symbol_names(buf: bytes) -> tuple[list[str], list[str]]:
    exports = [feature.value for feature, _ in extract_file_export_names(ELFFile(io.BytesIO(buf)))]
    imports = [feature.value for feature, _ in extract_file_import_names(ELFFile(io.BytesIO(buf)))]
    return exports, imports


def test_removed_gnu_hash_section():
    """
    a stale DT_GNU_HASH that points at a removed .gnu.hash section used to crash
    pyelftools with a ValueError from max() on an empty bucket list.

    the file is still perfectly analyzable: .gnu.hash is only a lookup accelerator,
    and DT_SYMTAB is untouched.

    see https://github.com/mandiant/capa/issues/3170
    """
    buf = Path(SAMPLE_PATH).read_bytes()
    expected_exports, expected_imports = get_symbol_names(buf)
    assert expected_imports

    exports, imports = get_symbol_names(remove_section(buf, ".gnu.hash"))

    assert imports == expected_imports
    assert exports == expected_exports


def test_removed_gnu_hash_section_without_section_headers():
    """
    the same, on a file that has no section headers to bound DT_SYMTAB with,
    so only the dynamic tags are left to go by.
    """
    buf = Path(SAMPLE_PATH).read_bytes()
    expected_exports, expected_imports = get_symbol_names(buf)

    stripped = remove_section_headers(remove_section(buf, ".gnu.hash"))
    exports, imports = get_symbol_names(stripped)

    assert imports == expected_imports
    # the exports of this sample come from .symtab, which the section headers describe
    assert exports == []


def test_removed_hash_tables_without_section_headers():
    """
    the same on a sample that carries both hash tables and no section headers.

    zero the head of each: DT_GNU_HASH is the one that raises, while a zeroed SysV
    DT_HASH raises nothing at all and reads back as zero symbols, so its symbols
    would go missing silently.
    """
    buf = Path(STRIPPED_SAMPLE_PATH).read_bytes()
    expected_exports, expected_imports = get_symbol_names(buf)
    assert expected_imports
    assert expected_exports

    # Gnu_Hash: nbuckets, symoffset, bloom_size, bloom_shift
    stripped = zero_dynamic_table(buf, "DT_GNU_HASH", 4 * 4)
    # Elf_Hash: nbuckets, nchains
    stripped = zero_dynamic_table(stripped, "DT_HASH", 2 * 4)

    exports, imports = get_symbol_names(stripped)

    assert imports == expected_imports
    assert exports == expected_exports


def test_gnu_hash_section_filled_with_junk():
    """
    a .gnu.hash filled with junk is worse than one that's been removed: pyelftools
    parses the table as soon as it builds the section object, so the file's sections
    and segments all become unreachable through it at once.

    we can't recover the dynamic symbols from such a file -- constructing a dynamic
    segment is what walks the sections looking for a string table -- but everything
    else about the file still reads, so don't give up on it.
    """
    buf = Path(SAMPLE_PATH).read_bytes()
    expected_exports, _ = get_symbol_names(buf)

    elf = ELFFile(io.BytesIO(buf))
    section = elf.get_section_by_name(".gnu.hash")
    assert section is not None

    b = bytearray(buf)
    b[section["sh_offset"] : section["sh_offset"] + section["sh_size"]] = b"\xff" * section["sh_size"]

    exports, _ = get_symbol_names(bytes(b))
    sections = [feature.value for feature, _ in extract_file_section_names(ELFFile(io.BytesIO(bytes(b))))]

    # the .symtab exports and the section names are unaffected
    assert exports == expected_exports
    assert ".dynsym" in sections


def test_dynamic_symbols_are_not_sized_by_the_hash_table():
    """
    a .gnu.hash table that covers only part of .dynsym used to hide the rest of the
    symbols: pyelftools sizes DT_SYMTAB from the hash table, which is not what the
    section header says.
    """
    path = fixtures.CD / "data" / "e17e6a79ed614f5468d0eed758629697.elf_"
    buf = Path(path).read_bytes()

    # `readelf --dyn-syms` reports 10 entries in .dynsym for this sample,
    # while the .gnu.hash table only accounts for 1.
    _, imports = get_symbol_names(buf)

    assert sorted(imports) == [
        "__libc_start_main",
        "calloc",
        "free",
        "malloc",
        "memcpy",
        "memmove",
        "memset",
        "realloc",
    ]


def retag_dynamic_tag(buf: bytes, old_tag: int, new_tag: int) -> bytes:
    """rewrite the d_tag of the first matching entry of the dynamic tag array"""
    elf = ELFFile(io.BytesIO(buf))
    assert elf.elfclass == 64, "only implemented for ELF64"
    assert elf.little_endian, "only implemented for little endian"

    dynamic = elf.get_section_by_name(".dynamic")
    assert dynamic is not None, "sample has no .dynamic section"

    b = bytearray(buf)
    # Elf64_Dyn: { Elf64_Sxword d_tag; union { Elf64_Xword d_val; Elf64_Addr d_ptr; } }
    for i in range(dynamic["sh_size"] // 16):
        offset = dynamic["sh_offset"] + i * 16
        (d_tag,) = struct.unpack_from("<q", b, offset)
        if d_tag == old_tag:
            struct.pack_into("<q", b, offset, new_tag)
            return bytes(b)

    raise AssertionError(f"sample has no dynamic tag {old_tag}")


def test_relocation_table_without_its_size_tag():
    """
    a DT_RELA without its companion DT_RELASZ used to abort the run with
    `RuntimeError: generator raised StopIteration`: pyelftools reaches for the missing
    tag with a bare `next()`, from inside one of our generators.
    """
    DT_RELASZ = 8
    DT_FLAGS = 30

    buf = Path(SAMPLE_PATH).read_bytes()
    expected_exports, _ = get_symbol_names(buf)

    # rewrite DT_RELASZ into a tag that pyelftools won't go looking for
    exports, imports = get_symbol_names(retag_dynamic_tag(buf, DT_RELASZ, DT_FLAGS))

    # the relocations are what name the imports, so those are gone; the rest still reads
    assert imports == []
    assert exports == expected_exports
