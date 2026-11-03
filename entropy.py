import math
from dataclasses import dataclass, field
from typing import List


HIGH_ENTROPY_THRESHOLD = 7.2


@dataclass
class EntropyWindowSample:
    offset: int
    length: int
    entropy: float
    is_high_entropy: bool


@dataclass
class HighEntropyRegion:
    start_offset: int
    end_offset: int
    peak_entropy: float
    mean_entropy: float

    @property
    def size(self) -> int:
        return max(0, self.end_offset - self.start_offset)


@dataclass
class EntropyProfile:
    global_entropy: float
    window_size: int
    threshold: float
    samples: List[EntropyWindowSample] = field(default_factory=list)
    high_entropy_regions: List[HighEntropyRegion] = field(default_factory=list)
    heatmap_buckets: List[float] = field(default_factory=list)


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Compute exact Shannon Entropy in bits per byte [0.0 .. 8.0]:
        H(X) = - sum_{i=0}^{255} P(x_i) * log2(P(x_i))
    """
    total = len(data)
    if total == 0:
        return 0.0

    counts = [0] * 256
    for b in data:
        counts[b] += 1

    entropy = 0.0
    inv_total = 1.0 / float(total)
    for c in counts:
        if c > 0:
            p = c * inv_total
            entropy -= p * math.log2(p)

    return round(min(8.0, max(0.0, entropy)), 4)


def classify_entropy_level(entropy_val: float) -> str:
    """
    Classify Shannon entropy value into structural strata levels.
    """
    if entropy_val >= HIGH_ENTROPY_THRESHOLD:
        return "HIGH (Packed / Encrypted / Compressed)"
    if entropy_val >= 6.5:
        return "ELEVATED (Dense Native Code / RoData)"
    if entropy_val >= 5.0:
        return "NORMAL (Standard Code / Data)"
    return "LOW (Sparse / Padding / Text)"


def analyze_stream_entropy(
    data: bytes,
    window_size: int = 512,
    threshold: float = HIGH_ENTROPY_THRESHOLD,
    num_heatmap_buckets: int = 48,
) -> EntropyProfile:
    """
    Perform sliding-window Shannon entropy analysis across the binary stream
    (configurable window: 256 to 1024+ bytes) and coalesce contiguous ranges
    exceeding `threshold` (default 7.2 bits/byte).
    """
    window_size = max(256, min(65536, int(window_size)))
    global_h = calculate_shannon_entropy(data)
    total_len = len(data)

    if total_len == 0:
        return EntropyProfile(
            global_entropy=0.0,
            window_size=window_size,
            threshold=threshold,
        )

    step = max(128, int(window_size / 2))
    if total_len > step * 4096:
        step = max(window_size, int(total_len / 2048))

    samples: List[EntropyWindowSample] = []
    pos = 0
    while pos < total_len:
        chunk = data[pos : min(total_len, pos + window_size)]
        h_val = calculate_shannon_entropy(chunk)
        is_high = h_val >= threshold
        samples.append(
            EntropyWindowSample(
                offset=pos,
                length=len(chunk),
                entropy=h_val,
                is_high_entropy=is_high,
            )
        )
        if pos + window_size >= total_len:
            break
        pos += step

    regions: List[HighEntropyRegion] = []
    active_start: int = -1
    active_end: int = -1
    active_vals: List[float] = []

    for s in samples:
        if s.is_high_entropy:
            if active_start == -1:
                active_start = s.offset
                active_end = s.offset + s.length
                active_vals = [s.entropy]
            else:
                active_end = max(active_end, s.offset + s.length)
                active_vals = active_vals + [s.entropy]
        else:
            if active_start != -1:
                regions.append(
                    HighEntropyRegion(
                        start_offset=active_start,
                        end_offset=active_end,
                        peak_entropy=round(max(active_vals), 4),
                        mean_entropy=round(sum(active_vals) / len(active_vals), 4),
                    )
                )
                active_start = -1
                active_end = -1
                active_vals = []

    if active_start != -1 and active_vals:
        regions.append(
            HighEntropyRegion(
                start_offset=active_start,
                end_offset=active_end,
                peak_entropy=round(max(active_vals), 4),
                mean_entropy=round(sum(active_vals) / len(active_vals), 4),
            )
        )

    buckets: List[float] = []
    bucket_count = max(8, min(80, num_heatmap_buckets))
    if total_len <= 256:
        buckets = [global_h for _ in range(bucket_count)]
    else:
        min_probe = min(total_len, max(256, window_size))
        for b_idx in range(bucket_count):
            b_start = int((b_idx * total_len) / bucket_count)
            b_end = int(((b_idx + 1) * total_len) / bucket_count)
            span = b_end - b_start
            if span < min_probe:
                center = int((b_start + b_end) / 2)
                half = int(min_probe / 2)
                s_pos = max(0, min(total_len - min_probe, center - half))
                b_slice = data[s_pos : s_pos + min_probe]
            else:
                b_slice = data[b_start:b_end]
            buckets.append(calculate_shannon_entropy(b_slice))

    return EntropyProfile(
        global_entropy=global_h,
        window_size=window_size,
        threshold=threshold,
        samples=samples,
        high_entropy_regions=regions,
        heatmap_buckets=buckets,
    )
