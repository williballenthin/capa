# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from typing import Dict, List, Optional

from pydantic import Field, BaseModel
from typing_extensions import Annotated
from pydantic.functional_validators import BeforeValidator


def validate_hex_int(value):
    if isinstance(value, str):
        return int(value, 16) if value.startswith("0x") else int(value, 10)
    else:
        return value


HexInt = Annotated[int, BeforeValidator(validate_hex_int)]


# models flog.xml files
class FunctionCall(BaseModel):
    ts: HexInt
    fncall_id: HexInt
    process_id: HexInt
    thread_id: HexInt
    name: str
    addr: str
    from_addr: str = Field(alias="from")


class FunctionReturn(BaseModel):
    ts: HexInt
    fncall_id: HexInt
    addr: str
    from_addr: str = Field(alias="from")


class Analysis(BaseModel):
    log_version: str
    analyzer_version: str
    analysis_date: str

    function_calls: List[FunctionCall] = Field(alias="fncall", default=[])
    function_returns: List[FunctionReturn] = Field(alias="fnret", default=[])


class Flog(BaseModel):
    analysis: Analysis


# models for summary_v2.json files
class GenericReference(BaseModel):
    path: List[str]
    source: str


class StaticDataReference(GenericReference): ...


class PEFileBasicInfo(BaseModel):
    # compile_time: str
    file_type: str
    image_base: int
    machine_type: str
    # size_of_code: int
    # size_of_initialized_data: int
    # size_of_uninitialized_data: int
    # subsystem: str
    # entry_point: int
    # imphash: Optional[str] = None


class API(BaseModel):
    name: str
    ordinal: Optional[int] = None


class PEFileExport(BaseModel):
    address: int
    api: API


class PEFileImport(BaseModel):
    address: int
    api: API
    # thunk_offset: int
    # hint: Optional[int] = None
    # thunk_rva: int


class PEFileImportModule(BaseModel):
    dll: str
    apis: List[PEFileImport]


class PEFileSection(BaseModel):
    # entropy: float
    # flags: List[str] = []
    name: str
    # raw_data_offset: int
    # raw_data_size: int
    virtual_address: int
    # virtual_size: int


class PEFile(BaseModel):
    basic_info: PEFileBasicInfo
    exports: List[PEFileExport] = []
    imports: List[PEFileImportModule] = []
    sections: List[PEFileSection] = []


class StaticData(BaseModel):
    pe: Optional[PEFile] = None


class FileHashes(BaseModel):
    md5: str
    sha1: str
    sha256: str
    # ssdeep: str


class File(BaseModel):
    # categories: List[str]
    hash_values: FileHashes
    # is_artifact: bool
    # is_ioc: bool
    is_sample: bool
    # size: int
    # is_truncated: bool
    # mime_type: Optional[str] = None
    # operations: List[str] = []
    # ref_filenames: List[GenericReference] = []
    # ref_gfncalls: List[GenericReference] = []
    ref_static_data: Optional[StaticDataReference] = None
    # ref_vti_matches: List[GenericReference] = []
    # verdict: str


class Process(BaseModel):
    # bitness: int
    # is_artifact: bool
    # is_ioc: bool
    monitor_id: int
    # monitor_reason: str
    os_pid: int
    filename: str
    image_name: str
    ref_parent_process: Optional[GenericReference] = None


class Filename(BaseModel):
    filename: str
    # is_artifact: bool
    # is_ioc: bool
    # verdict: str


class Mutex(BaseModel):
    name: str
    # is_artifact: bool
    # is_ioc: bool
    # verdict: str


class Registry(BaseModel):
    reg_key_name: str
    # reg_key_value_type: Optional[str] = None
    # is_artifact: bool
    # is_ioc: bool
    # verdict: str


class Domain(BaseModel):
    domain: str
    # is_artifact: bool
    # is_ioc: bool
    # verdict: str


class IPAddress(BaseModel):
    ip_address: str
    # is_artifact: bool
    # is_ioc: bool
    # verdict: str


class AnalysisMetadata(BaseModel):
    sample_type: str
    submission_filename: str


class SummaryV2(BaseModel):
    analysis_metadata: AnalysisMetadata

    static_data: Dict[str, StaticData] = {}

    # recorded artifacts
    files: Dict[str, File] = {}
    processes: Dict[str, Process] = {}
    filenames: Dict[str, Filename] = {}
    mutexes: Dict[str, Mutex] = {}
    domains: Dict[str, Domain] = {}
    ip_addresses: Dict[str, IPAddress] = {}
    registry_records: Dict[str, Registry] = {}
