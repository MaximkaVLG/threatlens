"""Frequency-domain features for network flows.

Standard CIC-IDS2017 features capture statistical moments of inter-arrival
times (mean / std / min / max). They miss *temporal structure* — the
periodicity of botnet C2 beacons, the broadband signature of high-rate
floods, the low-frequency dominance of slowloris-style slow attacks.

These 8 features expose that structure via FFT and autocorrelation.
They are network-invariant: they describe the *shape* of timing patterns,
not absolute durations, so they should generalise across networks better
than raw IAT statistics.

All features default to 0.0 for flows too short for stable spectra
(< 10 packets) — the model can learn this is an "uninformative" signal.
"""
from __future__ import annotations

from typing import Dict, List

import numpy as np
from scipy.fft import fft

# Names match the CIC-IDS2017 column-naming convention (Title Case, spaces).
# These are exposed alongside CIC_FEATURE_COLUMNS to downstream code.
SPECTRAL_FEATURE_COLUMNS: List[str] = [
    "Spectral Peak Freq",         # dominant frequency in IAT spectrum (Hz)
    "Spectral Peak Magnitude",    # FFT amplitude at the dominant frequency
    "Spectral Entropy",           # Shannon entropy of normalised spectrum (broadband vs narrow)
    "Spectral Centroid",          # frequency-weighted mean (Hz)
    "Spectral Bandwidth",         # weighted std around centroid (Hz)
    "Low Freq Energy Ratio",      # share of energy below 1 Hz (slowloris signature)
    "IAT Periodicity Score",      # max non-trivial autocorrelation of IATs (botnet beacon)
    "IAT Zero Crossing Rate",     # rate at which IATs cross their mean (jitter measure)
]

_MIN_PACKETS = 10  # below this, spectra are too noisy to be useful


def compute_spectral_features(timestamps_us: List[int]) -> Dict[str, float]:
    """Compute 8 spectral features from packet timestamps in microseconds.

    Robust to: empty input, single packet, zero IAT std, zero spectrum.
    Returns a dict with all 8 keys present (zeros if input is degenerate).
    """
    out: Dict[str, float] = {col: 0.0 for col in SPECTRAL_FEATURE_COLUMNS}

    if len(timestamps_us) < _MIN_PACKETS:
        return out

    ts_sec = np.asarray(sorted(timestamps_us), dtype=np.float64) / 1_000_000.0
    iats = np.diff(ts_sec)
    if len(iats) < 4 or iats.std() == 0:
        return out

    mean_iat = float(iats.mean())
    if mean_iat <= 0:
        return out

    iats_detrended = iats - mean_iat

    spectrum = np.abs(fft(iats_detrended))
    n_one_sided = len(spectrum) // 2
    if n_one_sided < 2:
        return out
    spectrum = spectrum[:n_one_sided]
    total_energy = float(spectrum.sum())
    if total_energy == 0:
        return out

    freqs = np.fft.fftfreq(len(iats_detrended), d=mean_iat)[:n_one_sided]

    peak_idx = int(np.argmax(spectrum))
    out["Spectral Peak Freq"] = float(freqs[peak_idx])
    out["Spectral Peak Magnitude"] = float(spectrum[peak_idx])

    spec_norm = spectrum / total_energy
    nz = spec_norm[spec_norm > 0]
    out["Spectral Entropy"] = float(-(nz * np.log2(nz)).sum())

    centroid = float((freqs * spectrum).sum() / total_energy)
    out["Spectral Centroid"] = centroid
    out["Spectral Bandwidth"] = float(np.sqrt(((freqs - centroid) ** 2 * spec_norm).sum()))

    low_band = freqs < 1.0
    if low_band.any():
        out["Low Freq Energy Ratio"] = float(spectrum[low_band].sum() / total_energy)

    if len(iats_detrended) >= 8:
        ac = np.correlate(iats_detrended, iats_detrended, mode="full")
        ac = ac[ac.size // 2:]
        ac0 = float(ac[0])
        if ac0 > 0:
            ac_norm = np.abs(ac / ac0)
            # Skip lag 0 and lag 1 (always high for any signal); look for true periodicity
            out["IAT Periodicity Score"] = float(ac_norm[2:].max())

    sign_changes = int(np.sum(np.diff(np.sign(iats_detrended)) != 0))
    out["IAT Zero Crossing Rate"] = float(sign_changes / max(len(iats_detrended) - 1, 1))

    return out
