import datetime
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550
PE32_MAGIC = 0x010B
PE32_PLUS_MAGIC = 0x020B

MACHINE_TYPES: Dict[int, str] = {
    0x0000: "UNKNOWN",
    0x014C: "x86 (I386)",
    0x0200: "IA64 (Itanium)",
    0x8664: "x64 (AMD64)",
    0x01C0: "ARM",
    0x01C4: "ARMv7 (Thumb-2)",
    0xAA64: "ARM64 (AArch64)",
}

SUBSYSTEM_TYPES: Dict[int, str] = {
    0: "UNKNOWN",
    1: "NATIVE (Driver / Kernel)",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI (Console)",
    5: "OS2_CUI",
    7: "POSIX_CUI",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER",
    13: "EFI_ROM",
    14: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
}

FILE_CHARACTERISTICS: Dict[int, str] = {
    0x0001: "RELOCS_STRIPPED",
    0x0002: "EXECUTABLE_IMAGE",
    0x0004: "LINE_NUMS_STRIPPED",
    0x0008: "LOCAL_SYMS_STRIPPED",
    0x0020: "LARGE_ADDRESS_AWARE",
    0x0100: "32BIT_MACHINE",
    0x0200: "DEBUG_STRIPPED",
    0x0400: "REMOVABLE_RUN_FROM_SWAP",
    0x0800: "NET_RUN_FROM_SWAP",
    0x1000: "SYSTEM",
    0x2000: "DLL",
    0x4000: "UP_SYSTEM_ONLY",
}

SECTION_CHARACTERISTICS: Dict[int, str] = {
    0x00000020: "CNT_CODE",
    0x00000040: "CNT_INITIALIZED_DATA",
    0x00000080: "CNT_UNINITIALIZED_DATA",
    0x02000000: "MEM_DISCARDABLE",
    0x04000000: "MEM_NOT_CACHED",
    0x08000000: "MEM_NOT_PAGED",
    0x10000000: "MEM_SHARED",
    0x20000000: "MEM_EXECUTE",
    0x40000000: "MEM_READ",
    0x80000000: "MEM_WRITE",
}

CRITICAL_APIS = {
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "NtQueueApcThread",
    "OpenProcess",
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "CreateProcessA",
    "CreateProcessW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "InternetOpenA",
    "InternetOpenUrlA",
    "CryptEncrypt",
    "CryptDecrypt",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "RegSetValueExA",
    "RegSetValueExW",
}


class PEFormatError(Exception):
    """Raised when a binary fails static PE/COFF structural validation."""


@dataclass
class DOSHeader:
    e_magic: int
    e_lfanew: int


@dataclass
class COFFFileHeader:
    machine: int
    machine_str: str
    number_of_sections: int
    time_date_stamp: int
    timestamp_utc: str
    pointer_to_symbol_table: int
    number_of_symbols: int
    size_of_optional_header: int
    characteristics: int
    characteristics_flags: List[str]


@dataclass
class DataDirectoryEntry:
    name: str
    index: int
    virtual_address: int
    size: int


@dataclass
class OptionalHeaderInfo:
    magic: int
    pe_format: str
    linker_version: str
    size_of_code: int
    address_of_entry_point: int
    base_of_code: int
    image_base: int
    section_alignment: int
    file_alignment: int
    size_of_image: int
    size_of_headers: int
    checksum: int
    subsystem: int
    subsystem_str: str
    dll_characteristics: int
    number_of_rva_and_sizes: int
    data_directories: List[DataDirectoryEntry] = field(default_factory=list)


@dataclass
class SectionHeaderInfo:
    index: int
    name: str
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    characteristics: int
    flags: List[str]
    permission_rwx: str
    raw_bytes: bytes = field(default=b"", repr=False)
    entropy: float = 0.0
    anomalies: List[str] = field(default_factory=list)


@dataclass
class ImportedFunction:
    name: str
    ordinal: Optional[int]
    hint: int
    is_critical: bool


@dataclass
class ImportedDLL:
    dll_name: str
    original_first_thunk: int
    first_thunk: int
    functions: List[ImportedFunction] = field(default_factory=list)


@dataclass
class AuthenticodeInfo:
    present: bool
    file_offset: int
    size: int
    revision: int = 0
    certificate_type: int = 0
    certificate_type_str: str = "NONE"
    valid_bounds: bool = False


@dataclass
class PEAnalysisReport:
    filepath: str
    file_size: int
    dos_header: DOSHeader
    file_header: COFFFileHeader
    optional_header: OptionalHeaderInfo
    sections: List[SectionHeaderInfo]
    imports: List[ImportedDLL]
    authenticode: AuthenticodeInfo
    warnings: List[str] = field(default_factory=list)


def _decode_flags(value: int, table: Dict[int, str]) -> List[str]:
    return [label for bit, label in table.items() if (value & bit) != 0]


def _format_rwx(chars: int) -> str:
    r = "R" if (chars & 0x40000000) else "-"
    w = "W" if (chars & 0x80000000) else "-"
    x = "X" if (chars & 0x20000000) else "-"
    return f"{r}{w}{x}"


def _read_cstring(data: bytes, offset: int, max_len: int = 256) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, min(len(data), offset + max_len))
    if end == -1:
        end = min(len(data), offset + max_len)
    return data[offset:end].decode("ascii", errors="replace")


def rva_to_file_offset(
    rva: int, sections: List[SectionHeaderInfo], size_of_headers: int
) -> Optional[int]:
    if rva == 0:
        return None
    if rva < size_of_headers:
        return rva
    for sec in sections:
        v_start = sec.virtual_address
        span = max(sec.virtual_size, sec.size_of_raw_data)
        if span > 0 and v_start <= rva < v_start + span:
            delta = rva - v_start
            if delta < sec.size_of_raw_data:
                return sec.pointer_to_raw_data + delta
    return None


def parse_pe_bytes(data: bytes, filepath: str = "<memory>") -> PEAnalysisReport:
    """
    Parse a Portable Executable binary from raw bytes with exhaustive bounds checking.
    """
    warnings: List[str] = []
    file_size = len(data)
    if file_size < 64:
        raise PEFormatError(
            f"File too small ({file_size} bytes) to contain a valid DOS header."
        )

    e_magic, e_lfanew = struct.unpack_from("<H58xI", data, 0)
    if e_magic != IMAGE_DOS_SIGNATURE:
        raise PEFormatError(
            f"Invalid IMAGE_DOS_SIGNATURE: expected 0x5A4D ('MZ'), found 0x{e_magic:04X}."
        )
    if e_lfanew < 0x40 or e_lfanew + 24 > file_size:
        raise PEFormatError(
            f"Corrupted e_lfanew pointer (0x{e_lfanew:08X}) outside file boundary ({file_size} B)."
        )

    dos_hdr = DOSHeader(e_magic=e_magic, e_lfanew=e_lfanew)

    nt_sig = struct.unpack_from("<I", data, e_lfanew)[0]
    if nt_sig != IMAGE_NT_SIGNATURE:
        raise PEFormatError(
            f"Invalid IMAGE_NT_SIGNATURE at 0x{e_lfanew:08X}: expected 0x00004550 ('PE\\0\\0'), found 0x{nt_sig:08X}."
        )

    coff_offset = e_lfanew + 4
    (
        machine,
        num_sections,
        time_date_stamp,
        ptr_sym_table,
        num_symbols,
        size_opt_hdr,
        characteristics,
    ) = struct.unpack_from("<HHIIIHH", data, coff_offset)

    try:
        ts_dt = datetime.datetime.fromtimestamp(
            time_date_stamp, tz=datetime.timezone.utc
        )
        ts_str = ts_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        ts_str = f"INVALID (0x{time_date_stamp:08X})"
        warnings.append(f"Non-standard COFF TimeDateStamp: 0x{time_date_stamp:08X}")

    file_hdr = COFFFileHeader(
        machine=machine,
        machine_str=MACHINE_TYPES.get(machine, f"UNKNOWN (0x{machine:04X})"),
        number_of_sections=num_sections,
        time_date_stamp=time_date_stamp,
        timestamp_utc=ts_str,
        pointer_to_symbol_table=ptr_sym_table,
        number_of_symbols=num_symbols,
        size_of_optional_header=size_opt_hdr,
        characteristics=characteristics,
        characteristics_flags=_decode_flags(characteristics, FILE_CHARACTERISTICS),
    )

    opt_offset = coff_offset + 20
    if size_opt_hdr < 24 or opt_offset + size_opt_hdr > file_size:
        raise PEFormatError(
            f"Corrupted Optional Header bounds (offset 0x{opt_offset:X}, size {size_opt_hdr} B)."
        )

    opt_magic = struct.unpack_from("<H", data, opt_offset)[0]
    is_pe32_plus = opt_magic == PE32_PLUS_MAGIC
    if opt_magic not in (PE32_MAGIC, PE32_PLUS_MAGIC):
        raise PEFormatError(
            f"Unsupported Optional Header Magic: 0x{opt_magic:04X} (expected 0x010B PE32 or 0x020B PE32+)."
        )

    if is_pe32_plus:
        if opt_offset + 112 > file_size:
            raise PEFormatError("Truncated PE32+ Optional Header.")
        (
            magic,
            maj_ln,
            min_ln,
            sz_code,
            sz_init,
            sz_uninit,
            ep,
            base_code,
            image_base,
            sec_align,
            file_align,
            maj_os,
            min_os,
            maj_img,
            min_img,
            maj_sub,
            min_sub,
            win32_ver,
            sz_image,
            sz_headers,
            checksum,
            subsystem,
            dll_chars,
            sz_stack_res,
            sz_stack_com,
            sz_heap_res,
            sz_heap_com,
            loader_flags,
            num_rva_sizes,
        ) = struct.unpack_from("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", data, opt_offset)
        dd_offset = opt_offset + 112
        pe_fmt_str = "PE32+ (64-bit)"
    else:
        if opt_offset + 96 > file_size:
            raise PEFormatError("Truncated PE32 Optional Header.")
        (
            magic,
            maj_ln,
            min_ln,
            sz_code,
            sz_init,
            sz_uninit,
            ep,
            base_code,
            base_data,
            image_base,
            sec_align,
            file_align,
            maj_os,
            min_os,
            maj_img,
            min_img,
            maj_sub,
            min_sub,
            win32_ver,
            sz_image,
            sz_headers,
            checksum,
            subsystem,
            dll_chars,
            sz_stack_res,
            sz_stack_com,
            sz_heap_res,
            sz_heap_com,
            loader_flags,
            num_rva_sizes,
        ) = struct.unpack_from("<HBBIIIIIII" + "IIHHHHHHIIIIHHIIIIII", data, opt_offset)
        dd_offset = opt_offset + 96
        pe_fmt_str = "PE32 (32-bit)"

    dd_names = [
        "EXPORT",
        "IMPORT",
        "RESOURCE",
        "EXCEPTION",
        "SECURITY",
        "BASERELOC",
        "DEBUG",
        "ARCHITECTURE",
        "GLOBALPTR",
        "TLS",
        "LOAD_CONFIG",
        "BOUND_IMPORT",
        "IAT",
        "DELAY_IMPORT",
        "COM_DESCRIPTOR",
        "RESERVED",
    ]
    max_dirs = min(num_rva_sizes, 16)
    data_dirs: List[DataDirectoryEntry] = []
    for idx in range(max_dirs):
        entry_off = dd_offset + (idx * 8)
        if entry_off + 8 > opt_offset + size_opt_hdr or entry_off + 8 > file_size:
            break
        rva, sz = struct.unpack_from("<II", data, entry_off)
        data_dirs.append(
            DataDirectoryEntry(
                name=dd_names[idx],
                index=idx,
                virtual_address=rva,
                size=sz,
            )
        )

    opt_hdr = OptionalHeaderInfo(
        magic=opt_magic,
        pe_format=pe_fmt_str,
        linker_version=f"{maj_ln}.{min_ln}",
        size_of_code=sz_code,
        address_of_entry_point=ep,
        base_of_code=base_code,
        image_base=image_base,
        section_alignment=sec_align,
        file_alignment=file_align,
        size_of_image=sz_image,
        size_of_headers=sz_headers,
        checksum=checksum,
        subsystem=subsystem,
        subsystem_str=SUBSYSTEM_TYPES.get(subsystem, f"UNKNOWN ({subsystem})"),
        dll_characteristics=dll_chars,
        number_of_rva_and_sizes=num_rva_sizes,
        data_directories=data_dirs,
    )

    sec_table_offset = opt_offset + size_opt_hdr
    sections: List[SectionHeaderInfo] = []
    if num_sections > 96:
        warnings.append(
            f"Unusually high NumberOfSections ({num_sections}); clamping scan to 96."
        )
        num_sections = 96

    for i in range(num_sections):
        s_off = sec_table_offset + (i * 40)
        if s_off + 40 > file_size:
            warnings.append(
                f"Section header #{i} truncated at offset 0x{s_off:X}."
            )
            break
        (
            raw_name,
            v_size,
            v_addr,
            raw_size,
            raw_ptr,
            ptr_reloc,
            ptr_ln,
            num_reloc,
            num_ln,
            s_chars,
        ) = struct.unpack_from("<8sIIIIIIHHI", data, s_off)

        sec_name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace").strip()
        if not sec_name:
            sec_name = f"sec_{i}"

        anomalies: List[str] = []
        if (s_chars & 0x80000000) and (s_chars & 0x20000000):
            anomalies.append("W+X (Writable & Executable)")
        if raw_size == 0 and v_size > 0:
            anomalies.append("VIRTUAL_ONLY (Unpacked BSS/Stub)")
        if v_size > 0 and raw_size > 0 and (v_size > raw_size * 4):
            anomalies.append("HIGH_VSIZE_RATIO (Possible Packer)")

        if raw_ptr > 0 and raw_size > 0:
            if raw_ptr >= file_size:
                anomalies.append("RAW_PTR_OUT_OF_BOUNDS")
                sec_bytes = b""
            else:
                if raw_ptr + raw_size > file_size:
                    anomalies.append("RAW_TRUNCATED")
                sec_bytes = data[raw_ptr : min(file_size, raw_ptr + raw_size)]
        else:
            sec_bytes = b""

        sections.append(
            SectionHeaderInfo(
                index=i,
                name=sec_name,
                virtual_size=v_size,
                virtual_address=v_addr,
                size_of_raw_data=raw_size,
                pointer_to_raw_data=raw_ptr,
                characteristics=s_chars,
                flags=_decode_flags(s_chars, SECTION_CHARACTERISTICS),
                permission_rwx=_format_rwx(s_chars),
                raw_bytes=sec_bytes,
                anomalies=anomalies,
            )
        )

    ep_in_exec_sec = False
    for sec in sections:
        span = max(sec.virtual_size, sec.size_of_raw_data)
        if sec.virtual_address <= ep < sec.virtual_address + span:
            ep_in_exec_sec = True
            if not (sec.characteristics & 0x20000000):
                sec.anomalies.append("EP_IN_NON_EXEC_SECTION")
                warnings.append(
                    f"EntryPoint (0x{ep:08X}) resides in non-executable section '{sec.name}'."
                )
            break
    if ep != 0 and sections and not ep_in_exec_sec:
        warnings.append(
            f"AddressOfEntryPoint (0x{ep:08X}) does not map inside any declared section."
        )

    imports = _parse_import_directory(
        data=data,
        data_dirs=data_dirs,
        sections=sections,
        size_of_headers=sz_headers,
        is_pe32_plus=is_pe32_plus,
        warnings=warnings,
    )

    authenticode = _parse_security_directory(
        data=data,
        data_dirs=data_dirs,
        warnings=warnings,
    )

    return PEAnalysisReport(
        filepath=filepath,
        file_size=file_size,
        dos_header=dos_hdr,
        file_header=file_hdr,
        optional_header=opt_hdr,
        sections=sections,
        imports=imports,
        authenticode=authenticode,
        warnings=warnings,
    )


def _parse_import_directory(
    data: bytes,
    data_dirs: List[DataDirectoryEntry],
    sections: List[SectionHeaderInfo],
    size_of_headers: int,
    is_pe32_plus: bool,
    warnings: List[str],
) -> List[ImportedDLL]:
    if len(data_dirs) <= 1:
        return []
    imp_dir = data_dirs[1]
    if imp_dir.virtual_address == 0 or imp_dir.size == 0:
        return []

    imp_offset = rva_to_file_offset(imp_dir.virtual_address, sections, size_of_headers)
    if imp_offset is None or imp_offset + 20 > len(data):
        warnings.append(
            f"Import Directory RVA 0x{imp_dir.virtual_address:08X} could not be mapped to file offset."
        )
        return []

    imported_dlls: List[ImportedDLL] = []
    pos = imp_offset
    max_descriptors = 256

    for _ in range(max_descriptors):
        if pos + 20 > len(data):
            break
        oft, ts, fwd, name_rva, ft = struct.unpack_from("<IIIII", data, pos)
        if oft == 0 and name_rva == 0 and ft == 0:
            break
        pos += 20

        name_off = rva_to_file_offset(name_rva, sections, size_of_headers)
        dll_name = _read_cstring(data, name_off) if name_off is not None else f"RVA_0x{name_rva:X}"
        if not dll_name:
            dll_name = f"UNKNOWN_DLL_0x{name_rva:X}"

        thunk_rva = oft if oft != 0 else ft
        thunk_off = rva_to_file_offset(thunk_rva, sections, size_of_headers)
        funcs: List[ImportedFunction] = []

        if thunk_off is not None:
            t_pos = thunk_off
            ptr_size = 8 if is_pe32_plus else 4
            ordinal_flag = 0x8000000000000000 if is_pe32_plus else 0x80000000
            fmt_code = "<Q" if is_pe32_plus else "<I"

            for _ in range(2048):
                if t_pos + ptr_size > len(data):
                    break
                thunk_val = struct.unpack_from(fmt_code, data, t_pos)[0]
                if thunk_val == 0:
                    break
                t_pos += ptr_size

                if thunk_val & ordinal_flag:
                    ord_num = int(thunk_val & 0xFFFF)
                    funcs.append(
                        ImportedFunction(
                            name=f"Ordinal#{ord_num}",
                            ordinal=ord_num,
                            hint=0,
                            is_critical=False,
                        )
                    )
                else:
                    ibn_rva = int(thunk_val & 0x7FFFFFFF)
                    ibn_off = rva_to_file_offset(ibn_rva, sections, size_of_headers)
                    if ibn_off is not None and ibn_off + 2 < len(data):
                        hint = struct.unpack_from("<H", data, ibn_off)[0]
                        fn_name = _read_cstring(data, ibn_off + 2, max_len=256)
                        funcs.append(
                            ImportedFunction(
                                name=fn_name or f"Hint_{hint}",
                                ordinal=None,
                                hint=hint,
                                is_critical=(fn_name in CRITICAL_APIS),
                            )
                        )

        imported_dlls.append(
            ImportedDLL(
                dll_name=dll_name,
                original_first_thunk=oft,
                first_thunk=ft,
                functions=funcs,
            )
        )

    return imported_dlls


def _parse_security_directory(
    data: bytes,
    data_dirs: List[DataDirectoryEntry],
    warnings: List[str],
) -> AuthenticodeInfo:
    """
    Inspect Data Directory 4 (IMAGE_DIRECTORY_ENTRY_SECURITY).
    Note: In PE specifications, Data Directory 4 VirtualAddress is a direct file pointer (offset), not an RVA.
    """
    if len(data_dirs) <= 4:
        return AuthenticodeInfo(present=False, file_offset=0, size=0)

    sec_dir = data_dirs[4]
    if sec_dir.virtual_address == 0 or sec_dir.size == 0:
        return AuthenticodeInfo(present=False, file_offset=0, size=0)

    cert_off = sec_dir.virtual_address
    cert_size = sec_dir.size
    valid_bounds = (cert_off >= 64) and (cert_off + cert_size <= len(data))

    revision = 0
    cert_type = 0
    cert_type_str = "UNKNOWN"
    if cert_off + 8 <= len(data):
        dw_length, revision, cert_type = struct.unpack_from("<IHH", data, cert_off)
        cert_types = {
            0x0001: "X.509",
            0x0002: "PKCS#7 SignedData (Authenticode)",
            0x0003: "RESERVED",
            0x0004: "TS_STACK_SIGNED",
        }
        cert_type_str = cert_types.get(cert_type, f"TYPE_0x{cert_type:04X}")
    else:
        warnings.append(
            f"Security Directory offset (0x{cert_off:X}) exceeds physical file size."
        )

    return AuthenticodeInfo(
        present=True,
        file_offset=cert_off,
        size=cert_size,
        revision=revision,
        certificate_type=cert_type,
        certificate_type_str=cert_type_str,
        valid_bounds=valid_bounds,
    )


def parse_pe_file(filepath: str) -> Tuple[PEAnalysisReport, bytes]:
    """
    Open target PE file in strict read-only binary mode ('rb') and parse all headers.
    """
    with open(filepath, "rb") as fh:
        raw_data = fh.read()
    report = parse_pe_bytes(raw_data, filepath=filepath)
    return report, raw_data
