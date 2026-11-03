# bin-strata

`[ bin-strata : static pe structural dissector ]`

`bin-strata` is a modular, read-only Portable Executable (PE32 / PE32+) static structural inspector, Shannon Entropy visualization engine, and overlay detector written in Python 3.8+. It dissects PE/COFF headers natively using Python's standard `struct` module—without executing the binary or relying on external C bindings—and renders an interactive dark-mode diagnostic report via `rich`.

## System Architecture

```text
+-------------------------------------------------------------------------+
|                                main.py                                  |
|  CLI Parser (--target, --entropy-window, --carve-overlay, --export-json)|
|  Interactive Terminal Menu + tkinter File Dialog + Sample PE Generator  |
+------------------+-----------------+-----------------+------------------+
                   |                 |                 |
                   v                 v                 v
+----------------------+ +-----------------------+ +----------------------+
|     pe_parser.py     | |      entropy.py       | |      overlay.py      |
| - DOS Header (MZ)    | | - Global H(X) Formula | | - Max Raw Section    |
| - COFF File Header   | | - Per-Section H(X)    | |   Boundary Resolver  |
| - Optional Header    | | - Sliding Window      | | - Physical Disk Size |
|   (PE32 / PE32+)     | |   Sampler (256-1024B) | |   Comparison         |
| - Section Table      | | - High-Randomness     | | - Magic Hint &       |
| - Import Dir (DD #1) | |   Strata Detector     | |   Overlay Carver     |
| - Security (DD #4)   | |   (H > 7.2 bits/byte) | |                      |
+----------+-----------+ +-----------+-----------+ +----------+-----------+
           |                         |                        |
           +-------------------------+------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                                 ui.py                                   |
|  Rich Dark-Mode Telemetry (Cyan, Deep Blue, Steel Grey, Bright White)   |
|  - Header & Identity Panel          - Segmented Entropy Heatmap Bar     |
|  - Section Breakdown Matrix         - Import Directory & Critical APIs  |
|  - Overlay & Slack Space Panel      - Structural Anomaly Warnings       |
+-------------------------------------------------------------------------+
```

## PE/COFF Structural Dissection

1. **DOS Header (`IMAGE_DOS_HEADER`)**: Verifies `IMAGE_DOS_SIGNATURE` (`0x5A4D` / `MZ`) at offset `0x00` and validates the 32-bit `e_lfanew` offset at `0x3C` against physical file boundaries.
2. **NT & COFF File Header (`IMAGE_NT_HEADERS`)**: Verifies `IMAGE_NT_SIGNATURE` (`0x00004550` / `PE\0\0`), extracts target machine architecture (`x86`, `x64`, `ARM64`), `NumberOfSections`, `TimeDateStamp` (decoded to UTC), and `Characteristics` bitflags.
3. **Optional Header (`PE32` vs `PE32+`)**: Branches on `Magic` (`0x010B` for 32-bit `PE32`, `0x020B` for 64-bit `PE32+`), extracting `AddressOfEntryPoint`, `ImageBase`, `SectionAlignment`, `FileAlignment`, `SizeOfImage`, `SizeOfHeaders`, `Subsystem`, and the `DataDirectory` array.
4. **Section Headers Table**: Iterates over 40-byte `IMAGE_SECTION_HEADER` entries, computing `VirtualSize / SizeOfRawData` ratios, permission triples (`RWX`), section-level Shannon entropy, and structural anomalies (`W+X` writable-executable sections, unmapped entry points, or truncated raw data).
5. **Import Directory (Data Directory 1) & Security Directory (Data Directory 4)**: Translates RVAs to file offsets across section mappings to enumerate imported DLL descriptors, resolved API names/ordinals (highlighting process injection, memory allocation, and crypto APIs), and Authenticode PKCS#7 certificate containers.

## Mathematical Breakdown of Shannon Entropy

`bin-strata` measures byte randomness across the entire binary, each individual section, and a configurable sliding window ($W \in [256, 1024]$ bytes) using Claude Shannon's information entropy formula:

$$H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$

where $P(x_i) = \frac{c_i}{N}$ is the observed frequency of byte value $i \in [0, 255]$ in a buffer of length $N$ bytes.

- **$0.0 \le H(X) < 5.0$ (Low - Muted Grey `░`)**: Zero-padded blocks, import string tables, or wide-character resources.
- **$5.0 \le H(X) < 6.6$ (Normal - Deep Blue `▒`)**: Standard compiled x86/x64 machine instructions and initialized data sections.
- **$6.6 \le H(X) < 7.2$ (Dense - Bright Cyan `▓`)**: Dense compiler optimizations, read-only lookup tables, or uncompressed media assets.
- **$7.2 \le H(X) \le 8.0$ (High - Warning Gold `█`)**: Compressed, packed (e.g., UPX/Themida), or encrypted payloads.

## CLI Parameters

| Flag | Long Option | Default | Description |
| :--- | :--- | :--- | :--- |
| `-t` | `--target` | Interactive Menu | Target PE file path (`.exe`, `.dll`, `.sys`) or `sample` to generate and scan a synthetic PE32+ binary |
| `-w` | `--entropy-window` | `512` | Sliding-window sample size in bytes (`256` to `1024`) for high-entropy region detection |
| `-c` | `--carve-overlay` | `None` | File or directory path to extract an appended overlay byte blob if detected |
| `-j` | `--export-json` | `None` | Path to write the structured JSON analysis report |
| `-v` | `--verbose` | `False` | Enable verbose diagnostic output |

## Sample Terminal Output Preview

```text
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  [ bin-strata : static pe structural dissector ]                             ┃
┃  NATIVE COFF PARSER  |  SHANNON ENTROPY HEATMAP  |  OVERLAY CARVER           ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
┏━━━━━━━━━━━━━━━━━━━━━━━━━━ [ HEADER & FILE IDENTITY ] ━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Target Binary:        sample_strata_pe64.exe  PE Format:       PE32+ (64-bit)┃
┃ Architecture:         x64 (AMD64)             Physical Size:   2,772 bytes   ┃
┃ Compile Timestamp:    2025-11-03 02:40:00 UTC EntryPoint:      0x00001000    ┃
┃ ImageBase:            0x0000000140000000      Subsystem:       WINDOWS_CUI   ┃
┃ Section / File Align: 0x1000 / 0x200          Global Entropy:  6.5517 bits/B ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
┏━━━━━━━━━━━━━━━━ [ SHANNON ENTROPY HEATMAP & ANOMALY STRATA ] ━━━━━━━━━━━━━━━━┓
┃ Sliding Window: 512 B  |  Global H(X): 6.5517  |  High-Entropy Strata: 2     ┃
┃ ░░░░░░░░░▓▓▓▓▓▓▓▓▓░░░░░░░░░░█████████████████████▓▓▓▓                        ┃
┃ Legend: ░ Low (<5.0)  ▒ Normal (5.0-6.6)  ▓ Dense (6.6-7.2)  █ High (>7.2)   ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```
