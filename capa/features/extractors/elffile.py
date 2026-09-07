# Copyright 2021 Google LLC
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
import logging
import itertools
from typing import Iterator, Optional
from pathlib import Path

from elftools.elf.dynamic import DynamicSegment
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Symbol, SymbolTableSection
from elftools.elf.sections import Section as ElfSection
from elftools.elf.segments import Segment
from elftools.common.exceptions import ELFError

import capa.features.extractors.common
from capa.features.file import Export, Import, Section
from capa.features.common import OS, FORMAT_ELF, Arch, Format, Feature
from capa.features.address import NO_ADDRESS, Address, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import SampleHashes, StaticFeatureExtractor

logger = logging.getLogger(__name__)

# exceptions that pyelftools raises when it stumbles over a malformed ELF structure.
#
# ideally this would just be ELFError, which is what pyelftools raises deliberately,
# and which capa.main already translates into a clean "corrupt file" exit. but bad
# input also reaches code that isn't looking for it, so built-in exceptions escape
# from deep within the library and abort the whole run.
#
# so, treat all of these as "this ELF is malformed", and keep the scope of each
# handler down to the pyelftools call that may raise, so we don't mask our own bugs.
#
# see https://github.com/mandiant/capa/issues/3170
CORRUPT_ELF_ERRORS = (
    ELFError,
    # max() of the empty bucket list of a zero-filled .gnu.hash
    ValueError,
    # a .gnu.hash chain walk that runs past the end of the file
    struct.error,
    # a DT_STRTAB that can't be resolved, on pyelftools >= 0.33 (a bare assert),
    # and on earlier versions (a None dereference)
    AssertionError,
    AttributeError,
    # a table whose offset couldn't be resolved, which pyelftools passes along as None
    # and then does arithmetic with
    TypeError,
    # a section header index that's out of range
    IndexError,
    OverflowError,
)

# the dynamic tags whose value is an address. every other tag stores a size, a count,
# or an offset into the string table in that same union, so a scan for "the table that
# comes after DT_SYMTAB" has to skip them, or a byte count like DT_PLTRELSZ gets
# mistaken for the end of the symbol table.
#
# via https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.dynamic.html
# and https://github.com/eliben/pyelftools/blob/v0.33/elftools/elf/enums.py
ADDRESS_DYNAMIC_TAGS = frozenset((
    "DT_PLTGOT",
    "DT_HASH",
    "DT_STRTAB",
    "DT_SYMTAB",
    "DT_RELA",
    "DT_INIT",
    "DT_FINI",
    "DT_REL",
    "DT_JMPREL",
    "DT_INIT_ARRAY",
    "DT_FINI_ARRAY",
    "DT_PREINIT_ARRAY",
    "DT_SYMINFO",
    "DT_MOVETAB",
    "DT_VERSYM",
    "DT_VERDEF",
    "DT_VERNEED",
    "DT_RELR",
    "DT_PLTPAD",
    "DT_GNU_HASH",
    "DT_GNU_LIBLIST",
    "DT_GNU_CONFLICT",
    "DT_TLSDESC_PLT",
    "DT_TLSDESC_GOT",
    "DT_ANDROID_REL",
    "DT_ANDROID_RELA",
))

# when nothing bounds the dynamic symbol table, stop here rather than walk a corrupt
# file to its end. no real binary comes close: the largest .dynsym tables in the wild
# hold on the order of 100,000 entries.
MAX_DYNAMIC_SYMBOLS = 0x40000


def get_dynamic_tag_value(segment: DynamicSegment, name: str) -> Optional[int]:
    """fetch the value of the given dynamic tag, or None when it's absent or unreadable"""
    try:
        tag = next(segment.iter_tags(name), None)
    except CORRUPT_ELF_ERRORS as e:
        logger.debug("failed to read dynamic tag %s: %s", name, e)
        return None

    if tag is None:
        return None

    return tag["d_val"]


def iter_sections(elf: ELFFile) -> Iterator[ElfSection]:
    """
    enumerate an ELF's sections, skipping the ones that can't be parsed.

    pyelftools parses the contents of some section types as soon as it constructs the
    section object -- a GNU hash section, for example -- so without this, a single
    corrupt section makes every section of the file unreachable.
    """
    try:
        num_sections = elf.num_sections()
    except CORRUPT_ELF_ERRORS as e:
        logger.debug("failed to count sections: %s", e)
        return

    for i in range(num_sections):
        try:
            section = elf.get_section(i)
        except CORRUPT_ELF_ERRORS as e:
            logger.debug("failed to read section %d: %s", i, e)
            continue

        yield section


def iter_segments(elf: ELFFile) -> Iterator[Segment]:
    """
    enumerate an ELF's segments, skipping the ones that can't be parsed.

    like `iter_sections`: constructing a dynamic segment walks the sections looking for
    its string table, so a corrupt section shouldn't cost us the segments, either.
    """
    try:
        num_segments = elf.num_segments()
    except CORRUPT_ELF_ERRORS as e:
        logger.debug("failed to count segments: %s", e)
        return

    for i in range(num_segments):
        try:
            segment = elf.get_segment(i)
        except CORRUPT_ELF_ERRORS as e:
            logger.debug("failed to read segment %d: %s", i, e)
            continue

        yield segment


def get_dynsym_section_count(elf: ELFFile, tab_ptr: int) -> Optional[int]:
    """
    the number of entries in DT_SYMTAB, according to the section header that describes it.

    a section header is not load bearing, so a file can carry a false one and still run;
    but it does survive `strip --remove-section=.gnu.hash`, and where it exists it gives
    the number of entries exactly, rather than just an upper bound.
    """
    for section in iter_sections(elf):
        if not isinstance(section, SymbolTableSection):
            continue

        if section["sh_type"] != "SHT_DYNSYM":
            continue

        if section["sh_entsize"] == 0:
            continue

        if section["sh_addr"] != tab_ptr:
            # this section describes some other table than the one DT_SYMTAB points at
            continue

        return section["sh_size"] // section["sh_entsize"]

    return None


def get_dynamic_tag_bound(elf: ELFFile, segment: DynamicSegment, tab_ptr: int) -> Optional[int]:
    """
    an upper bound on the number of entries in DT_SYMTAB: the symbol table has to end
    before the table that follows it begins.

    this is only an upper bound, and a loose one when the layout is page aligned, so it
    wants a terminator to go with it. the scan also has to be careful: it considers only
    the tags that hold an address, and looks no further than DT_STRTAB, which
    conventionally comes right after the symbol table.
    """
    strtab_ptr, _ = segment.get_table_offset("DT_STRTAB")
    if strtab_ptr is None or strtab_ptr <= tab_ptr:
        # some toolchains, notably Go, lay .dynstr out *below* .dynsym. then nothing caps
        # the scan, and the nearest address above DT_SYMTAB (DT_PLTGOT, say) can sit far
        # past the end of the table, so don't guess.
        return None

    nearest_ptr = strtab_ptr
    try:
        for tag in segment.iter_tags():
            if tag["d_tag"] not in ADDRESS_DYNAMIC_TAGS:
                continue

            if tab_ptr < tag["d_ptr"] < nearest_ptr:
                nearest_ptr = tag["d_ptr"]
    except CORRUPT_ELF_ERRORS as e:
        logger.debug("failed to scan dynamic tags: %s", e)
        return None

    return (nearest_ptr - tab_ptr) // elf.structs.Elf_Sym.sizeof()


def get_dynamic_symbols(elf: ELFFile, segment: DynamicSegment) -> Iterator[tuple[int, Symbol]]:
    """
    enumerate the symbols of the dynamic symbol table, yielding each alongside its index.

    this is `DynamicSegment.iter_symbols`, except that it doesn't ask
    `DynamicSegment.num_symbols` how long the table is. that routine sizes the table from
    the DT_GNU_HASH or DT_HASH hash table, which is only a lookup accelerator, and which
    may be stale or removed while DT_SYMTAB itself is intact and the file still runs:

      - a zero-filled .gnu.hash, which is what `strip --remove-section=.gnu.hash` leaves
        behind, has no buckets, and pyelftools crashes on it outright.
      - a removed SysV .hash reads back as zero symbols, silently.
      - a tag retargeted at junk yields a nonsense count.

    so bound the table ourselves, and stop as soon as an entry stops looking like a symbol.

    see https://github.com/mandiant/capa/issues/3170
    """
    tab_ptr, tab_offset = segment.get_table_offset("DT_SYMTAB")
    if tab_ptr is None or tab_offset is None:
        logger.debug("dynamic segment doesn't contain DT_SYMTAB")
        return

    # prefer the count from the section header, which is exact where it exists. fall back
    # to the tag scan, which only says where the table has to end at the latest.
    num_symbols = get_dynsym_section_count(elf, tab_ptr)
    is_exact = num_symbols is not None
    if not is_exact:
        num_symbols = get_dynamic_tag_bound(elf, segment, tab_ptr)

    logger.debug(
        "dynamic segment contains %s symbols",
        num_symbols if is_exact else "at most %s" % num_symbols,
    )

    # an entry whose name lies outside the string table isn't a symbol. this cuts the
    # table short when the count is too large, including when a file carries a section
    # header that claims more entries than it has.
    #
    # a missing or zero DT_STRSZ tells us nothing about where names end, so don't let
    # it cut the table at the first entry.
    strsz = get_dynamic_tag_value(segment, "DT_STRSZ") or None

    for i in itertools.count():
        if num_symbols is not None and i >= num_symbols:
            break

        if i >= MAX_DYNAMIC_SYMBOLS:
            logger.debug("too many dynamic symbols, stopping after %d", i)
            break

        try:
            symbol = segment.get_symbol(i)
        except CORRUPT_ELF_ERRORS as e:
            logger.debug("failed to read dynamic symbol %d: %s", i, e)
            break

        # index 0 is the reserved undefined symbol, which has no name.
        if i > 0:
            if strsz is not None and symbol.entry.st_name >= strsz:
                logger.debug("dynamic symbol %d is named outside the string table", i)
                break

            if not is_exact and not symbol.name:
                # we don't know exactly where the table ends, so let the first nameless
                # entry mark it. the entry just past a real table reads as nameless
                # either way: through an st_name that points beyond the string table, or
                # through the zero padding that follows.
                break

        yield i, symbol


def get_section_symbols(section: SymbolTableSection) -> Iterator[Symbol]:
    """enumerate the symbols of a symbol table section, stopping if it turns out to be malformed"""
    try:
        num_symbols = section.num_symbols()
    except CORRUPT_ELF_ERRORS as e:
        logger.debug("failed to size symbol table '%s': %s", section.name, e)
        return

    logger.debug("symbol table '%s' contains %d entries", section.name, num_symbols)

    for i in range(num_symbols):
        try:
            symbol = section.get_symbol(i)
        except CORRUPT_ELF_ERRORS as e:
            logger.debug("failed to read symbol %d of '%s': %s", i, section.name, e)
            return

        yield symbol


def extract_file_export_names(elf: ELFFile, **kwargs):
    for section in iter_sections(elf):
        if not isinstance(section, SymbolTableSection):
            continue

        if section["sh_entsize"] == 0:
            logger.debug("Symbol table '%s' has a sh_entsize of zero!", section.name)
            continue

        for symbol in get_section_symbols(section):
            # The following conditions are based on the following article
            # http://www.m4b.io/elf/export/binary/analysis/2015/05/25/what-is-an-elf-export.html
            if not symbol.name:
                continue
            if symbol.entry.st_info.type not in ["STT_FUNC", "STT_OBJECT", "STT_IFUNC"]:
                continue
            if symbol.entry.st_value == 0:
                continue
            if symbol.entry.st_shndx == "SHN_UNDEF":
                continue

            yield Export(symbol.name), AbsoluteVirtualAddress(symbol.entry.st_value)

    for segment in iter_segments(elf):
        if not isinstance(segment, DynamicSegment):
            continue

        for _, symbol in get_dynamic_symbols(elf, segment):
            # The following conditions are based on the following article
            # http://www.m4b.io/elf/export/binary/analysis/2015/05/25/what-is-an-elf-export.html
            if not symbol.name:
                continue
            if symbol.entry.st_info.type not in ["STT_FUNC", "STT_OBJECT", "STT_IFUNC"]:
                continue
            if symbol.entry.st_value == 0:
                continue
            if symbol.entry.st_shndx == "SHN_UNDEF":
                continue

            yield Export(symbol.name), AbsoluteVirtualAddress(symbol.entry.st_value)


def extract_file_import_names(elf: ELFFile, **kwargs):
    symbol_name_by_index: dict[int, str] = {}

    # Extract symbol names and store them in the dictionary
    for segment in iter_segments(elf):
        if not isinstance(segment, DynamicSegment):
            continue

        for i, symbol in get_dynamic_symbols(elf, segment):
            # The following conditions are based on the following article
            # http://www.m4b.io/elf/export/binary/analysis/2015/05/25/what-is-an-elf-export.html
            if not symbol.name:
                continue
            if symbol.entry.st_info.type not in ["STT_FUNC", "STT_OBJECT", "STT_IFUNC"]:
                continue
            if symbol.entry.st_value != 0:
                continue
            if symbol.entry.st_shndx != "SHN_UNDEF":
                continue
            if symbol.entry.st_name == 0:
                continue

            symbol_name_by_index[i] = symbol.name

    for segment in iter_segments(elf):
        if not isinstance(segment, DynamicSegment):
            continue

        try:
            relocation_tables = segment.get_relocation_tables()
        except CORRUPT_ELF_ERRORS as e:
            logger.debug("failed to read relocation tables: %s", e)
            continue
        except StopIteration as e:
            # a relocation table tag without its companion size tag, such as DT_RELA
            # without DT_RELAENT. pyelftools reaches for the missing tag with a bare
            # `next()`, and because we're a generator, that StopIteration would
            # otherwise surface to our caller as a confusing RuntimeError.
            logger.debug("relocation table is missing a size tag: %s", e)
            continue

        logger.debug("Dynamic Segment contains %s relocation tables:", len(relocation_tables))

        for relocation_table in relocation_tables.values():
            try:
                num_relocations = relocation_table.num_relocations()
            except CORRUPT_ELF_ERRORS as e:
                logger.debug("failed to size relocation table: %s", e)
                continue

            relocations = []
            for i in range(num_relocations):
                try:
                    relocations.append(relocation_table.get_relocation(i))
                except CORRUPT_ELF_ERRORS:
                    # ELF is corrupt and the relocation table is invalid,
                    # so stop processing it.
                    break

            for relocation in relocations:
                if "r_info_sym" not in relocation.entry or "r_offset" not in relocation.entry:
                    continue

                symbol_address: int = relocation["r_offset"]
                symbol_index: int = relocation["r_info_sym"]

                if symbol_index not in symbol_name_by_index:
                    continue
                symbol_name = symbol_name_by_index[symbol_index]

                yield Import(symbol_name), AbsoluteVirtualAddress(symbol_address)


def extract_file_section_names(elf: ELFFile, **kwargs):
    for section in iter_sections(elf):
        if section.name:
            yield Section(section.name), AbsoluteVirtualAddress(section.header.sh_addr)
        elif section.is_null():
            yield Section("NULL"), AbsoluteVirtualAddress(section.header.sh_addr)


def extract_file_strings(buf, **kwargs):
    yield from capa.features.extractors.common.extract_file_strings(buf)


def extract_file_os(elf: ELFFile, buf, **kwargs):
    # our current approach does not always get an OS value, e.g. for packed samples
    # for file limitation purposes, we're more lax here
    try:
        os_tuple = next(capa.features.extractors.common.extract_os(buf))
        yield os_tuple
    except StopIteration:
        yield OS("unknown"), NO_ADDRESS


def extract_file_format(**kwargs):
    yield Format(FORMAT_ELF), NO_ADDRESS


def extract_file_arch(elf: ELFFile, **kwargs):
    arch = elf.get_machine_arch()
    if arch == "x86":
        yield Arch("i386"), NO_ADDRESS
    elif arch == "x64":
        yield Arch("amd64"), NO_ADDRESS
    elif arch == "ARM":
        yield Arch("arm"), NO_ADDRESS
    elif arch == "AArch64":
        yield Arch("aarch64"), NO_ADDRESS
    else:
        logger.warning("unsupported architecture: %s", arch)


def extract_file_features(elf: ELFFile, buf: bytes) -> Iterator[tuple[Feature, Address]]:
    for file_handler in FILE_HANDLERS:
        for feature, addr in file_handler(elf=elf, buf=buf):  # type: ignore
            yield feature, addr


FILE_HANDLERS = (
    extract_file_export_names,
    extract_file_import_names,
    extract_file_section_names,
    extract_file_strings,
    # no library matching
    extract_file_format,
)


def extract_global_features(elf: ELFFile, buf: bytes) -> Iterator[tuple[Feature, Address]]:
    for global_handler in GLOBAL_HANDLERS:
        for feature, addr in global_handler(elf=elf, buf=buf):  # type: ignore
            yield feature, addr


GLOBAL_HANDLERS = (
    extract_file_os,
    extract_file_arch,
)


class ElfFeatureExtractor(StaticFeatureExtractor):
    def __init__(self, path: Path):
        super().__init__(SampleHashes.from_bytes(path.read_bytes()))
        self.path: Path = path
        self.elf = ELFFile(io.BytesIO(path.read_bytes()))

    def get_base_address(self):
        for segment in iter_segments(self.elf):
            if segment.header.p_type == "PT_LOAD":
                return AbsoluteVirtualAddress(segment.header.p_vaddr)
        return NO_ADDRESS

    def extract_global_features(self) -> Iterator[tuple[Feature, Address]]:
        buf = self.path.read_bytes()

        for feature, addr in extract_global_features(self.elf, buf):
            yield feature, addr

    def extract_file_features(self) -> Iterator[tuple[Feature, Address]]:
        buf = self.path.read_bytes()

        for feature, addr in extract_file_features(self.elf, buf):
            yield feature, addr

    def get_functions(self):
        raise NotImplementedError("ElfFeatureExtractor can only be used to extract file features")

    def extract_function_features(self, fh):
        raise NotImplementedError("ElfFeatureExtractor can only be used to extract file features")

    def get_basic_blocks(self, fh):
        raise NotImplementedError("ElfFeatureExtractor can only be used to extract file features")

    def extract_basic_block_features(self, fh, bbh):
        raise NotImplementedError("ElfFeatureExtractor can only be used to extract file features")

    def get_instructions(self, fh, bbh):
        raise NotImplementedError("ElfFeatureExtractor can only be used to extract file features")

    def extract_insn_features(self, fh, bbh, ih):
        raise NotImplementedError("ElfFeatureExtractor can only be used to extract file features")

    def is_library_function(self, addr):
        raise NotImplementedError("ElfFeatureExtractor can only be used to extract file features")

    def get_function_name(self, addr):
        raise NotImplementedError("ElfFeatureExtractor can only be used to extract file features")
