# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import PE.carve as pe_carve  # vivisect PE
import viv_utils
import viv_utils.flirt

import capa.features.insn
import capa.features.extractors.helpers
import capa.features.extractors.strings
from capa.features.file import Export, Import, Section, FunctionName
from capa.features.common import String, Characteristic


def extract_file_embedded_pe(vw, buf):
    for offset, i in pe_carve.carve(buf, 1):
        yield Characteristic("embedded pe"), offset


def extract_file_export_names(vw, buf):
    for va, etype, name, _ in vw.getExports():
        yield Export(name), va


def extract_file_import_names(vw, buf):
    """
    extract imported function names
    1. imports by ordinal:
     - modulename.#ordinal
    2. imports by name, results in two features to support importname-only matching:
     - modulename.importname
     - importname
    """
    for va, _, _, tinfo in vw.getImports():
        # vivisect source: tinfo = "%s.%s" % (libname, impname)
        modname, impname = tinfo.split(".", 1)
        if is_viv_ord_impname(impname):
            # replace ord prefix with #
            impname = "#%s" % impname[len("ord") :]

        for name in capa.features.extractors.helpers.generate_symbols(modname, impname):
            yield Import(name), va


def is_viv_ord_impname(impname: str) -> bool:
    """
    return if import name matches vivisect's ordinal naming scheme `'ord%d' % ord`
    """
    if not impname.startswith("ord"):
        return False
    try:
        int(impname[len("ord") :])
    except ValueError:
        return False
    else:
        return True


def extract_file_section_names(vw, buf):
    for va, _, segname, _ in vw.getSegments():
        yield Section(segname), va


def extract_file_strings(vw, buf):
    """
    extract ASCII and UTF-16 LE strings from file
    """
    for s in capa.features.extractors.strings.extract_ascii_strings(buf):
        yield String(s.s), s.offset

    for s in capa.features.extractors.strings.extract_unicode_strings(buf):
        yield String(s.s), s.offset


def extract_file_function_names(vw, buf):
    """
    extract the names of statically-linked library functions.
    """
    for va in sorted(vw.getFunctions()):
        if viv_utils.flirt.is_library_function(vw, va):
            name = viv_utils.get_function_name(vw, va)
            yield FunctionName(name), va


def extract_features(vw, buf: bytes):
    """
    extract file features from given workspace

    args:
      vw (vivisect.VivWorkspace): the vivisect workspace
      buf: the raw input file bytes

    yields:
      Tuple[Feature, VA]: a feature and its location.
    """

    for file_handler in FILE_HANDLERS:
        for feature, va in file_handler(vw, buf):
            yield feature, va


FILE_HANDLERS = (
    extract_file_embedded_pe,
    extract_file_export_names,
    extract_file_import_names,
    extract_file_section_names,
    extract_file_strings,
    extract_file_function_names,
)
