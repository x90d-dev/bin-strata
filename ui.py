import shutil
import sys
from typing import List, Optional

from entropy import EntropyProfile, HIGH_ENTROPY_THRESHOLD
from overlay import OverlayReport
from pe_parser import PEAnalysisReport

try:
    from rich import box
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


HEADER_TITLE = "[ bin-strata : static pe structural dissector ]"


class StrataUI:
    """
    Dark-mode forensic console renderer using Cyan, Deep Blue, Steel Grey, and White accents.
    """

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose
        if RICH_AVAILABLE:
            term_cols = shutil.get_terminal_size((108, 30)).columns
            console_width = max(104, term_cols)
            self.console: Optional[Console] = Console(
                width=console_width, highlight=False, soft_wrap=True
            )
        else:
            self.console = None

    @staticmethod
    def sanitize(text: str) -> str:
        """
        Ensure double slashes never appear in any header, log message, or table string.
        """
        pair = "/" + "/"
        while pair in text:
            text = text.replace(pair, "/")
        return text

    def print_banner(self) -> None:
        if RICH_AVAILABLE and self.console is not None:
            header = Text()
            header.append("[ ", style="bold deep_sky_blue3")
            header.append("bin-strata", style="bold bright_cyan")
            header.append(" : ", style="bold grey62")
            header.append("static pe structural dissector", style="bold bright_white")
            header.append(" ]", style="bold deep_sky_blue3")

            sub = Text(
                "NATIVE COFF PARSER  |  SHANNON ENTROPY HEATMAP  |  OVERLAY CARVER",
                style="grey62",
            )
            panel = Panel(
                Group(header, sub),
                border_style="deep_sky_blue3",
                box=box.HEAVY,
                padding=(0, 2),
            )
            self.console.print(panel)
        else:
            line = "=" * len(HEADER_TITLE)
            sys.stdout.write(f"\n{line}\n{HEADER_TITLE}\n{line}\n")
            sys.stdout.flush()

    def log(self, tag: str, message: str) -> None:
        clean_msg = self.sanitize(message)
        tag_u = tag.upper()
        if RICH_AVAILABLE and self.console is not None:
            styles = {
                "INFO": "bold deep_sky_blue3",
                "PARSE": "bold bright_cyan",
                "STRATA": "bold bright_white",
                "WARN": "bold gold1",
                "CARVE": "bold magenta",
                "DONE": "bold bright_cyan",
            }
            st = styles.get(tag_u, "bold grey62")
            txt = Text()
            txt.append(f"[{tag_u}] ", style=st)
            txt.append(clean_msg, style="bright_white")
            self.console.print(txt)
        else:
            sys.stdout.write(f"[{tag_u}] {clean_msg}\n")
            sys.stdout.flush()

    def render_full_report(
        self,
        pe: PEAnalysisReport,
        entropy_profile: EntropyProfile,
        overlay: OverlayReport,
    ) -> None:
        if RICH_AVAILABLE and self.console is not None:
            self._render_rich_identity_table(pe, entropy_profile)
            self._render_rich_heatmap(entropy_profile)
            self._render_rich_section_matrix(pe)
            self._render_rich_imports_table(pe)
            self._render_rich_overlay_panel(overlay)
            if pe.warnings:
                self._render_rich_warnings(pe.warnings)
        else:
            self._render_plain_fallback(pe, entropy_profile, overlay)

    def _render_rich_identity_table(
        self, pe: PEAnalysisReport, entropy_profile: EntropyProfile
    ) -> None:
        assert self.console is not None
        grid = Table(
            box=box.SIMPLE_HEAVY,
            border_style="deep_sky_blue3",
            show_header=False,
            expand=True,
        )
        grid.add_column("Field1", style="bold grey62", width=21)
        grid.add_column("Val1", style="bright_white", ratio=1)
        grid.add_column("Field2", style="bold grey62", width=21)
        grid.add_column("Val2", style="bright_cyan", ratio=1)

        fh = pe.file_header
        oh = pe.optional_header
        auth_str = (
            f"PRESENT ({pe.authenticode.certificate_type_str}, {pe.authenticode.size} B)"
            if pe.authenticode.present
            else "UNSIGNED (No Security Dir)"
        )

        grid.add_row(
            "Target Binary:",
            self.sanitize(pe.filepath),
            "PE Format:",
            f"{oh.pe_format} (0x{oh.magic:04X})",
        )
        grid.add_row(
            "Architecture:",
            fh.machine_str,
            "Physical Size:",
            f"{pe.file_size:,} bytes (0x{pe.file_size:X})",
        )
        grid.add_row(
            "Compile Timestamp:",
            fh.timestamp_utc,
            "EntryPoint (RVA):",
            f"0x{oh.address_of_entry_point:08X}",
        )
        grid.add_row(
            "ImageBase:",
            f"0x{oh.image_base:016X}" if oh.magic == 0x20B else f"0x{oh.image_base:08X}",
            "Subsystem:",
            oh.subsystem_str,
        )
        grid.add_row(
            "Section / File Align:",
            f"0x{oh.section_alignment:X} / 0x{oh.file_alignment:X}",
            "Global Entropy:",
            f"{entropy_profile.global_entropy:.4f} bits/byte",
        )
        grid.add_row(
            "Characteristics:",
            ", ".join(fh.characteristics_flags[:4]) or f"0x{fh.characteristics:04X}",
            "Authenticode:",
            auth_str,
        )

        panel = Panel(
            grid,
            title=Text("[ HEADER & FILE IDENTITY ]", style="bold bright_cyan"),
            border_style="deep_sky_blue3",
            box=box.HEAVY,
        )
        self.console.print(panel)

    def _render_rich_heatmap(self, profile: EntropyProfile) -> None:
        assert self.console is not None
        bar = Text()
        for h_val in profile.heatmap_buckets:
            if h_val >= HIGH_ENTROPY_THRESHOLD:
                bar.append("█", style="bold gold1")
            elif h_val >= 6.6:
                bar.append("▓", style="bold bright_cyan")
            elif h_val >= 5.0:
                bar.append("▒", style="deep_sky_blue3")
            else:
                bar.append("░", style="grey50")

        legend = Text()
        legend.append("Legend: ", style="bold grey62")
        legend.append("░ Low (<5.0)  ", style="grey50")
        legend.append("▒ Normal (5.0-6.6)  ", style="deep_sky_blue3")
        legend.append("▓ Dense (6.6-7.2)  ", style="bold bright_cyan")
        legend.append("█ High/Packed (>7.2)", style="bold gold1")

        summary = Text()
        summary.append(
            f"Sliding Window: {profile.window_size} B  |  "
            f"Global H(X): {profile.global_entropy:.4f} bits/byte  |  "
            f"High-Entropy Strata (> {profile.threshold}): {len(profile.high_entropy_regions)} region(s)",
            style="bright_white",
        )

        items: List[object] = [summary, Text(""), bar, legend]
        if profile.high_entropy_regions:
            reg_table = Table(
                box=box.SIMPLE,
                border_style="grey50",
                header_style="bold gold1",
                expand=True,
            )
            reg_table.add_column("Region #", style="grey62", width=10)
            reg_table.add_column("Start Offset", style="bright_white")
            reg_table.add_column("End Offset", style="bright_white")
            reg_table.add_column("Span (Bytes)", justify="right", style="bright_cyan")
            reg_table.add_column("Peak H(X)", justify="right", style="bold gold1")
            reg_table.add_column("Mean H(X)", justify="right", style="bright_white")

            for idx, reg in enumerate(profile.high_entropy_regions[:8], start=1):
                reg_table.add_row(
                    f"#{idx}",
                    f"0x{reg.start_offset:08X}",
                    f"0x{reg.end_offset:08X}",
                    f"{reg.size:,} B",
                    f"{reg.peak_entropy:.4f}",
                    f"{reg.mean_entropy:.4f}",
                )
            items.append(reg_table)

        panel = Panel(
            Group(*items),
            title=Text("[ SHANNON ENTROPY HEATMAP & ANOMALY STRATA ]", style="bold bright_cyan"),
            border_style="deep_sky_blue3",
            box=box.HEAVY,
        )
        self.console.print(panel)

    def _render_rich_section_matrix(self, pe: PEAnalysisReport) -> None:
        assert self.console is not None
        table = Table(
            box=box.SIMPLE_HEAVY,
            border_style="deep_sky_blue3",
            header_style="bold bright_cyan",
            expand=True,
        )
        table.add_column("#", style="grey62", width=3, no_wrap=True)
        table.add_column("Name", style="bold bright_white", width=9, no_wrap=True)
        table.add_column("VirtAddr", style="deep_sky_blue3", justify="right", no_wrap=True)
        table.add_column("VirtSize", style="bright_white", justify="right", no_wrap=True)
        table.add_column("RawPtr", style="deep_sky_blue3", justify="right", no_wrap=True)
        table.add_column("RawSize", style="bright_white", justify="right", no_wrap=True)
        table.add_column("Ratio", style="grey62", justify="right", no_wrap=True)
        table.add_column("Perm", style="bright_cyan", justify="center", no_wrap=True)
        table.add_column("Entropy", justify="right", no_wrap=True)
        table.add_column("Anomaly Flags", style="gold1")

        for sec in pe.sections:
            ratio = (
                f"{sec.virtual_size / sec.size_of_raw_data:.2f}x"
                if sec.size_of_raw_data > 0
                else "INF"
            )
            if sec.entropy >= HIGH_ENTROPY_THRESHOLD:
                ent_cell = Text(f"{sec.entropy:.4f}", style="bold gold1")
            elif sec.entropy >= 6.5:
                ent_cell = Text(f"{sec.entropy:.4f}", style="bold bright_cyan")
            else:
                ent_cell = Text(f"{sec.entropy:.4f}", style="bright_white")

            flags_list = list(sec.anomalies)
            if sec.entropy >= HIGH_ENTROPY_THRESHOLD:
                flags_list.append("HIGH_ENTROPY (>7.2)")
            anomaly_str = ", ".join(flags_list) if flags_list else "CLEAN"

            table.add_row(
                str(sec.index),
                self.sanitize(sec.name),
                f"0x{sec.virtual_address:08X}",
                f"{sec.virtual_size:,}",
                f"0x{sec.pointer_to_raw_data:08X}",
                f"{sec.size_of_raw_data:,}",
                ratio,
                sec.permission_rwx,
                ent_cell,
                anomaly_str,
            )

        panel = Panel(
            table,
            title=Text("[ SECTION BREAKDOWN MATRIX ]", style="bold bright_cyan"),
            border_style="deep_sky_blue3",
            box=box.HEAVY,
        )
        self.console.print(panel)

    def _render_rich_imports_table(self, pe: PEAnalysisReport) -> None:
        assert self.console is not None
        table = Table(
            box=box.SIMPLE_HEAVY,
            border_style="deep_sky_blue3",
            header_style="bold bright_cyan",
            expand=True,
        )
        table.add_column("Library (DLL)", style="bold bright_white", width=24)
        table.add_column("Total APIs", justify="right", style="bright_cyan", width=12)
        table.add_column("Critical / Notable Resolved Symbols", style="grey62")

        if not pe.imports:
            table.add_row("NONE (Static / Packed IAT)", "0", "No Import Descriptors resolved")
        else:
            for dll in pe.imports:
                crit = [f.name for f in dll.functions if f.is_critical]
                regular = [f.name for f in dll.functions if not f.is_critical]
                preview_items: List[str] = []
                for c_api in crit[:6]:
                    preview_items.append(f"[!]{c_api}")
                for r_api in regular[: max(0, 6 - len(preview_items))]:
                    preview_items.append(r_api)
                summary_str = ", ".join(preview_items) if preview_items else "-"
                table.add_row(
                    self.sanitize(dll.dll_name),
                    str(len(dll.functions)),
                    self.sanitize(summary_str),
                )

        panel = Panel(
            table,
            title=Text("[ IMPORT DIRECTORY & API TELEMETRY ]", style="bold bright_cyan"),
            border_style="deep_sky_blue3",
            box=box.HEAVY,
        )
        self.console.print(panel)

    def _render_rich_overlay_panel(self, overlay: OverlayReport) -> None:
        assert self.console is not None
        grid = Table(
            box=box.SIMPLE,
            border_style="deep_sky_blue3",
            show_header=False,
            expand=True,
        )
        grid.add_column("Key", style="bold grey62", width=22)
        grid.add_column("Val", style="bright_white", ratio=1)
        grid.add_column("Key2", style="bold grey62", width=24)
        grid.add_column("Val2", style="bright_cyan", ratio=1)

        status_str = (
            "DETECTED (Appended Trailing Data)"
            if overlay.present
            else "NONE (Exact Section Alignment)"
        )
        grid.add_row(
            "Overlay Status:",
            status_str,
            "Expected PE Boundary:",
            f"0x{overlay.expected_pe_boundary:08X} ({overlay.expected_pe_boundary:,} B)",
        )
        grid.add_row(
            "Overlay Start Offset:",
            f"0x{overlay.overlay_offset:08X}",
            "Overlay Byte Length:",
            f"{overlay.overlay_size:,} B",
        )
        grid.add_row(
            "Overlay Entropy:",
            f"{overlay.overlay_entropy:.4f} bits/byte",
            "Payload Classification:",
            overlay.signature_hint,
        )
        if overlay.present:
            carve_state = (
                self.sanitize(overlay.carved_filepath)
                if overlay.carved_filepath
                else "Available (use --carve-overlay <path>)"
            )
            grid.add_row(
                "Overlay SHA-256:",
                overlay.sha256[:24] + "...",
                "Carve / Extraction:",
                carve_state,
            )

        panel = Panel(
            grid,
            title=Text("[ OVERLAY & SLACK SPACE REPORT ]", style="bold bright_cyan"),
            border_style="deep_sky_blue3",
            box=box.HEAVY,
        )
        self.console.print(panel)

    def _render_rich_warnings(self, warnings: List[str]) -> None:
        assert self.console is not None
        lines = [Text(f"• {self.sanitize(w)}", style="gold1") for w in warnings]
        panel = Panel(
            Group(*lines),
            title=Text("[ STRUCTURAL ANOMALIES & WARNINGS ]", style="bold gold1"),
            border_style="gold1",
            box=box.HEAVY,
        )
        self.console.print(panel)

    def _render_plain_fallback(
        self,
        pe: PEAnalysisReport,
        entropy_profile: EntropyProfile,
        overlay: OverlayReport,
    ) -> None:
        self.log(
            "INFO",
            f"Target: {pe.filepath} | {pe.optional_header.pe_format} | "
            f"Machine: {pe.file_header.machine_str} | Global Entropy: {entropy_profile.global_entropy:.4f}",
        )
        for sec in pe.sections:
            self.log(
                "STRATA",
                f"Section {sec.name:8s} | VSize: {sec.virtual_size:8d} | "
                f"RSize: {sec.size_of_raw_data:8d} | Perm: {sec.permission_rwx} | "
                f"Entropy: {sec.entropy:.4f}",
            )
        self.log(
            "INFO",
            f"Overlay Present: {overlay.present} | Offset: 0x{overlay.overlay_offset:08X} | "
            f"Size: {overlay.overlay_size} B | Entropy: {overlay.overlay_entropy:.4f}",
        )
