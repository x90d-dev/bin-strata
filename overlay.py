import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from entropy import HIGH_ENTROPY_THRESHOLD, calculate_shannon_entropy
from pe_parser import SectionHeaderInfo


@dataclass
class OverlayReport:
    present: bool
    expected_pe_boundary: int
    physical_file_size: int
    overlay_offset: int
    overlay_size: int
    overlay_entropy: float
    sha256: str
    signature_hint: str
    is_suspicious: bool
    carved_filepath: Optional[str] = None


def _identify_overlay_magic(blob: bytes) -> str:
    if len(blob) < 4:
        return "RAW_BYTES"
    if blob.startswith(b"PK\x03\x04"):
        return "PKZIP / SFX Archive"
    if blob.startswith(b"\x52\x61\x72\x21\x1a\x07"):
        return "RAR Archive"
    if blob.startswith(b"\x37\x7a\xbc\xaf\x27\x1c"):
        return "7-Zip Archive"
    if blob.startswith(b"\x1f\x8b\x08"):
        return "GZIP Stream"
    if blob.startswith(b"MZ"):
        return "Embedded PE / MZ Binary"
    if blob.startswith(b"%PDF"):
        return "Embedded PDF Document"
    if blob[:4] in (b"\x30\x82\x01\x0a", b"\x30\x82"):
        return "ASN.1 DER / PKCS#7 Signature Blob"
    return "Unstructured / Custom Overlay Blob"


def analyze_overlay(
    raw_data: bytes,
    size_of_headers: int,
    sections: List[SectionHeaderInfo],
    physical_file_size: Optional[int] = None,
) -> OverlayReport:
    """
    Determine highest raw byte offset across PE headers and all declared sections
    (PointerToRawData + SizeOfRawData) and compare with physical file size.
    """
    actual_size = (
        physical_file_size if physical_file_size is not None else len(raw_data)
    )
    highest_boundary = max(0, int(size_of_headers))

    for sec in sections:
        if sec.pointer_to_raw_data > 0 and sec.size_of_raw_data > 0:
            sec_end = sec.pointer_to_raw_data + sec.size_of_raw_data
            if sec_end > highest_boundary:
                highest_boundary = sec_end

    if highest_boundary > actual_size:
        highest_boundary = actual_size

    if actual_size > highest_boundary:
        overlay_offset = highest_boundary
        overlay_bytes = raw_data[overlay_offset:actual_size]
        overlay_size = len(overlay_bytes)
        overlay_h = calculate_shannon_entropy(overlay_bytes)
        digest = hashlib.sha256(overlay_bytes).hexdigest()
        sig_hint = _identify_overlay_magic(overlay_bytes)
        is_suspicious = (overlay_h >= HIGH_ENTROPY_THRESHOLD) or (
            "Archive" in sig_hint or "PE" in sig_hint
        )
        return OverlayReport(
            present=True,
            expected_pe_boundary=highest_boundary,
            physical_file_size=actual_size,
            overlay_offset=overlay_offset,
            overlay_size=overlay_size,
            overlay_entropy=overlay_h,
            sha256=digest,
            signature_hint=sig_hint,
            is_suspicious=is_suspicious,
        )

    return OverlayReport(
        present=False,
        expected_pe_boundary=highest_boundary,
        physical_file_size=actual_size,
        overlay_offset=highest_boundary,
        overlay_size=0,
        overlay_entropy=0.0,
        sha256="",
        signature_hint="NONE",
        is_suspicious=False,
    )


def carve_overlay_to_disk(
    raw_data: bytes,
    overlay_report: OverlayReport,
    output_path: str,
) -> Optional[str]:
    """
    Extract the raw appended overlay byte blob to `output_path` if an overlay is present.
    """
    if not overlay_report.present or overlay_report.overlay_size <= 0:
        return None

    target = Path(output_path)
    if target.is_dir():
        target = target / f"overlay_0x{overlay_report.overlay_offset:08X}.bin"
    else:
        target.parent.mkdir(parents=True, exist_ok=True)

    blob = raw_data[
        overlay_report.overlay_offset : overlay_report.overlay_offset
        + overlay_report.overlay_size
    ]
    target.write_bytes(blob)
    resolved = str(target.resolve())
    overlay_report.carved_filepath = resolved
    return resolved
