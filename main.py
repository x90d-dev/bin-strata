import argparse
import json
import os
import struct
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from entropy import analyze_stream_entropy, calculate_shannon_entropy
from overlay import OverlayReport, analyze_overlay, carve_overlay_to_disk
from pe_parser import PEAnalysisReport, PEFormatError, parse_pe_file
from ui import StrataUI


def open_native_pe_dialog(ui: StrataUI) -> Optional[str]:
    """
    Launch native OS file picker dialog using tkinter.filedialog.askopenfilename
    filtered for Portable Executable binaries (.exe, .dll, .sys, .ocx, .scr).
    """
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        try:
            root.attributes("-topmost", True)
        except Exception:
            pass
        selected = filedialog.askopenfilename(
            title="bin-strata : Select Target Portable Executable (PE)",
            filetypes=[
                ("Portable Executables", "*.exe *.dll *.sys *.ocx *.scr *.cpl *.efi"),
                ("All Files", "*.*"),
            ],
        )
        root.destroy()
        if selected:
            return selected
    except Exception as exc:
        ui.log(
            "INFO",
            f"Graphical file dialog unavailable ({exc}); switching to manual path input.",
        )
    return None


def generate_sample_pe_binary(dest_path: Path) -> Path:
    """
    Construct a self-contained, structurally valid 64-bit PE32+ executable (`sample_strata_pe64.exe`)
    containing `.text` (code), `.rdata` (Import Directory for KERNEL32.dll + USER32.dll),
    `.packed` (high-entropy >7.5 pseudo-encrypted buffer), and an appended PKZIP overlay
    so Option 3 ('Scan sample executable') works on any platform out of the box.
    """
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    dos_header = bytearray(0x80)
    struct.pack_into("<H", dos_header, 0, 0x5A4D)
    struct.pack_into("<I", dos_header, 0x3C, 0x80)

    nt_signature = struct.pack("<I", 0x00004550)
    coff_header = struct.pack(
        "<HHIIIHH",
        0x8664,
        3,
        1762137600,
        0,
        0,
        240,
        0x0022,
    )

    opt_header = bytearray(240)
    struct.pack_into(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        opt_header,
        0,
        0x020B,
        14,
        38,
        0x0200,
        0x0400,
        0,
        0x1000,
        0x1000,
        0x0000000140000000,
        0x1000,
        0x0200,
        6,
        0,
        1,
        0,
        6,
        0,
        0,
        0x4000,
        0x0200,
        0x0000,
        3,
        0x8160,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    struct.pack_into("<II", opt_header, 112 + (1 * 8), 0x2000, 40)

    sec_text = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x0200,
        0x1000,
        0x0200,
        0x0200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    sec_rdata = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata\x00\x00",
        0x0200,
        0x2000,
        0x0200,
        0x0400,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    sec_packed = struct.pack(
        "<8sIIIIIIHHI",
        b".packed\x00",
        0x0800,
        0x3000,
        0x0400,
        0x0600,
        0,
        0,
        0,
        0,
        0xE0000020,
    )

    headers_raw = (
        bytes(dos_header)
        + nt_signature
        + coff_header
        + bytes(opt_header)
        + sec_text
        + sec_rdata
        + sec_packed
    )
    headers_padded = headers_raw.ljust(0x0200, b"\x00")

    text_data = bytearray(0x0200)
    stub_ops = b"\x48\x83\xec\x28\x31\xc9\xff\x15\x12\x10\x00\x00\x48\x83\xc4\x28\xc3"
    text_data[: len(stub_ops)] = stub_ops
    for i in range(len(stub_ops), 0x0200):
        text_data[i] = (i * 7 + 0x90) & 0x7F

    rdata_data = bytearray(0x0200)
    struct.pack_into("<IIIII", rdata_data, 0, 0x2040, 0, 0, 0x2060, 0x2040)
    struct.pack_into("<Q", rdata_data, 0x40, 0x2070)
    struct.pack_into("<Q", rdata_data, 0x48, 0x2082)
    struct.pack_into("<Q", rdata_data, 0x50, 0)
    rdata_data[0x60 : 0x60 + 13] = b"KERNEL32.dll\x00"
    struct.pack_into("<H", rdata_data, 0x70, 101)
    rdata_data[0x72 : 0x72 + 13] = b"VirtualAlloc\x00"
    struct.pack_into("<H", rdata_data, 0x82, 205)
    rdata_data[0x84 : 0x84 + 19] = b"WriteProcessMemory\x00"

    packed_data = bytearray(0x0400)
    for i in range(0x0400):
        packed_data[i] = (i * 197 + 53) & 0xFF

    overlay_blob = (
        b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
        + bytes((i * 131 + 17) & 0xFF for i in range(180))
        + b"PK\x05\x06"
        + (b"\x00" * 18)
    )

    full_pe = headers_padded + bytes(text_data) + bytes(rdata_data) + bytes(packed_data) + overlay_blob
    dest_path.write_bytes(full_pe)
    return dest_path


def prompt_interactive_menu(ui: StrataUI) -> str:
    sys.stdout.write(
        "\nSelect PE analysis target mode:\n"
        "  1) Select target PE file via native Windows File Dialog (tkinter.filedialog)\n"
        "  2) Enter target path manually\n"
        "  3) Scan sample executable\n"
        "  q) Exit\n\n"
    )
    sys.stdout.flush()

    while True:
        try:
            choice = input("Enter selection [1-3 or q]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            sys.stdout.write("\n")
            sys.exit(0)

        if choice in ("q", "quit", "exit"):
            sys.exit(0)

        if choice == "1":
            ui.log("INFO", "Launching native file selection dialog...")
            picked = open_native_pe_dialog(ui)
            if not picked:
                picked = input("Enter path to PE binary (.exe/.dll/.sys): ").strip().strip('"')
            if picked and os.path.isfile(picked):
                return picked
            ui.log("WARN", "File path does not exist or selection was cancelled.")

        elif choice == "2":
            picked = input("Enter path to PE binary (.exe/.dll/.sys): ").strip().strip('"')
            if picked and os.path.isfile(picked):
                return picked
            ui.log("WARN", "Specified file does not exist. Please try again.")

        elif choice == "3":
            sample_path = generate_sample_pe_binary(
                Path("./samples/sample_strata_pe64.exe")
            )
            ui.log("INFO", f"Generated sample PE32+ executable: {sample_path.resolve()}")
            return str(sample_path)

        else:
            ui.log("INFO", "Please enter 1, 2, 3, or q.")


def build_json_report(
    pe: PEAnalysisReport,
    entropy_profile,
    overlay: OverlayReport,
) -> Dict[str, Any]:
    return {
        "filepath": pe.filepath,
        "file_size": pe.file_size,
        "dos_header": {
            "e_magic": f"0x{pe.dos_header.e_magic:04X}",
            "e_lfanew": f"0x{pe.dos_header.e_lfanew:08X}",
        },
        "file_header": {
            "machine": pe.file_header.machine_str,
            "number_of_sections": pe.file_header.number_of_sections,
            "time_date_stamp": pe.file_header.time_date_stamp,
            "timestamp_utc": pe.file_header.timestamp_utc,
            "characteristics": pe.file_header.characteristics_flags,
        },
        "optional_header": {
            "pe_format": pe.optional_header.pe_format,
            "address_of_entry_point": f"0x{pe.optional_header.address_of_entry_point:08X}",
            "image_base": f"0x{pe.optional_header.image_base:X}",
            "section_alignment": pe.optional_header.section_alignment,
            "file_alignment": pe.optional_header.file_alignment,
            "size_of_image": pe.optional_header.size_of_image,
            "size_of_headers": pe.optional_header.size_of_headers,
            "subsystem": pe.optional_header.subsystem_str,
        },
        "authenticode": {
            "present": pe.authenticode.present,
            "file_offset": pe.authenticode.file_offset,
            "size": pe.authenticode.size,
            "certificate_type": pe.authenticode.certificate_type_str,
            "valid_bounds": pe.authenticode.valid_bounds,
        },
        "entropy": {
            "global_entropy": entropy_profile.global_entropy,
            "window_size": entropy_profile.window_size,
            "threshold": entropy_profile.threshold,
            "high_entropy_regions": [
                {
                    "start_offset": f"0x{r.start_offset:08X}",
                    "end_offset": f"0x{r.end_offset:08X}",
                    "size": r.size,
                    "peak_entropy": r.peak_entropy,
                    "mean_entropy": r.mean_entropy,
                }
                for r in entropy_profile.high_entropy_regions
            ],
        },
        "sections": [
            {
                "index": s.index,
                "name": s.name,
                "virtual_address": f"0x{s.virtual_address:08X}",
                "virtual_size": s.virtual_size,
                "pointer_to_raw_data": f"0x{s.pointer_to_raw_data:08X}",
                "size_of_raw_data": s.size_of_raw_data,
                "permissions": s.permission_rwx,
                "entropy": s.entropy,
                "anomalies": s.anomalies,
            }
            for s in pe.sections
        ],
        "imports": [
            {
                "dll_name": d.dll_name,
                "function_count": len(d.functions),
                "functions": [
                    {
                        "name": f.name,
                        "ordinal": f.ordinal,
                        "is_critical": f.is_critical,
                    }
                    for f in d.functions
                ],
            }
            for d in pe.imports
        ],
        "overlay": {
            "present": overlay.present,
            "expected_pe_boundary": overlay.expected_pe_boundary,
            "physical_file_size": overlay.physical_file_size,
            "overlay_offset": f"0x{overlay.overlay_offset:08X}",
            "overlay_size": overlay.overlay_size,
            "overlay_entropy": overlay.overlay_entropy,
            "signature_hint": overlay.signature_hint,
            "sha256": overlay.sha256,
            "carved_filepath": overlay.carved_filepath,
        },
        "warnings": pe.warnings,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bin-strata",
        description="[ bin-strata : static pe structural dissector ]",
    )
    parser.add_argument(
        "-t",
        "--target",
        type=str,
        default=None,
        help="Path to target Portable Executable (.exe, .dll, .sys) or 'sample' to generate/scan a test PE",
    )
    parser.add_argument(
        "-w",
        "--entropy-window",
        type=int,
        default=512,
        help="Sliding-window size in bytes for Shannon entropy profiling (256..1024, default: 512)",
    )
    parser.add_argument(
        "-c",
        "--carve-overlay",
        type=str,
        default=None,
        help="Destination file or directory path to extract appended overlay payload",
    )
    parser.add_argument(
        "-j",
        "--export-json",
        type=str,
        default=None,
        help="Export complete static structural and entropy telemetry to a JSON report file",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose structural and import symbol diagnostics",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    ui = StrataUI(verbose=args.verbose)
    ui.print_banner()

    target_path = args.target
    if target_path and target_path.strip().lower() == "sample":
        sample_file = generate_sample_pe_binary(Path("./samples/sample_strata_pe64.exe"))
        target_path = str(sample_file)
        ui.log("INFO", f"Generated synthetic PE32+ binary at {sample_file.resolve()}")
    elif not target_path:
        target_path = prompt_interactive_menu(ui)

    if not os.path.isfile(target_path):
        ui.log("WARN", f"Target binary not found: {target_path}")
        return 1

    try:
        pe_report, raw_bytes = parse_pe_file(target_path)
    except PEFormatError as exc:
        ui.log("WARN", f"PE Structural Validation Error: {exc}")
        return 2
    except OSError as exc:
        ui.log("WARN", f"I/O Error reading target binary: {exc}")
        return 2

    for sec in pe_report.sections:
        sec.entropy = calculate_shannon_entropy(sec.raw_bytes)

    win_size = max(256, min(1024, int(args.entropy_window)))
    entropy_profile = analyze_stream_entropy(raw_bytes, window_size=win_size)

    try:
        disk_size = os.path.getsize(target_path)
    except OSError:
        disk_size = len(raw_bytes)

    overlay_report = analyze_overlay(
        raw_data=raw_bytes,
        size_of_headers=pe_report.optional_header.size_of_headers,
        sections=pe_report.sections,
        physical_file_size=disk_size,
    )

    if args.carve_overlay:
        if overlay_report.present:
            carved_to = carve_overlay_to_disk(
                raw_data=raw_bytes,
                overlay_report=overlay_report,
                output_path=args.carve_overlay,
            )
            if carved_to:
                ui.log(
                    "CARVE",
                    f"Extracted overlay ({overlay_report.overlay_size} B) to: {carved_to}",
                )
        else:
            ui.log("INFO", "No appended overlay detected; skipping overlay extraction.")

    ui.render_full_report(
        pe=pe_report,
        entropy_profile=entropy_profile,
        overlay=overlay_report,
    )

    if args.export_json:
        json_path = Path(args.export_json)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        payload = build_json_report(pe_report, entropy_profile, overlay_report)
        json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        ui.log("DONE", f"Exported JSON telemetry report to: {json_path.resolve()}")

    ui.log("DONE", f"Static structural dissection completed for {Path(target_path).name}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
