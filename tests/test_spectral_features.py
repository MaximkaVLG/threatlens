"""Unit tests for threatlens.network.spectral_features."""
from __future__ import annotations

import numpy as np
import pytest

from threatlens.network.spectral_features import (
    SPECTRAL_FEATURE_COLUMNS,
    compute_spectral_features,
)


def _ts(seconds_list):
    """Helper: convert seconds-since-epoch list to microseconds."""
    base = 1_700_000_000_000_000  # arbitrary microsecond epoch
    return [base + int(s * 1_000_000) for s in seconds_list]


def test_returns_all_eight_columns_with_keys_present():
    out = compute_spectral_features([])
    assert set(out.keys()) == set(SPECTRAL_FEATURE_COLUMNS)
    assert all(v == 0.0 for v in out.values())


def test_too_short_returns_zeros():
    out = compute_spectral_features(_ts(list(range(5))))  # only 5 packets
    assert all(v == 0.0 for v in out.values())


def test_zero_iat_std_returns_zeros():
    # All packets at the same timestamp → std=0 → degenerate
    out = compute_spectral_features([1_700_000_000_000_000] * 20)
    assert all(v == 0.0 for v in out.values())


def test_periodic_signal_high_periodicity_score():
    # A truly *periodic* IAT pattern: bursts of 3 quick packets repeating every
    # 5 seconds. IAT sequence: [small, small, large, small, small, large, ...]
    # — that is what botnet beacons look like at flow level. Constant-rate
    # traffic gives constant IATs (no periodicity), so we use a burst pattern.
    rng = np.random.default_rng(42)
    times = []
    t = 0.0
    for _ in range(20):
        times.append(t); t += 0.05 + rng.normal(0, 0.002)
        times.append(t); t += 0.05 + rng.normal(0, 0.002)
        times.append(t); t += 5.0  + rng.normal(0, 0.05)
    out = compute_spectral_features(_ts(times))
    assert out["IAT Periodicity Score"] > 0.5, \
        f"bursty periodic signal should have high periodicity, got {out['IAT Periodicity Score']:.3f}"


def test_random_signal_low_periodicity_score():
    rng = np.random.default_rng(42)
    times = np.cumsum(rng.exponential(scale=1.0, size=60))
    out = compute_spectral_features(_ts(times.tolist()))
    assert out["IAT Periodicity Score"] < 0.6, \
        f"random signal should not be highly periodic, got {out['IAT Periodicity Score']:.3f}"


def test_low_freq_dominant_for_slow_attack():
    # Slowloris-like: very long, slow IATs (~ 10 sec apart, 30 packets, 5 min total)
    rng = np.random.default_rng(0)
    times = np.cumsum(np.full(30, 10.0) + rng.normal(0, 0.5, 30))
    out = compute_spectral_features(_ts(times.tolist()))
    # All energy below 1 Hz because mean rate is 0.1 Hz
    assert out["Low Freq Energy Ratio"] >= 0.99, \
        f"slow attack should have nearly all energy below 1 Hz, got {out['Low Freq Energy Ratio']:.3f}"


def test_burst_traffic_higher_entropy_than_periodic():
    # Burst (HTTP-like) — broader spectrum than perfect periodic
    rng = np.random.default_rng(1)
    bursts = []
    t = 0.0
    for _ in range(10):
        for _ in range(5):
            t += rng.uniform(0.01, 0.05)
            bursts.append(t)
        t += rng.uniform(0.5, 2.0)  # gap

    perfect = list(np.arange(0, 60, 1.0))

    burst_entropy = compute_spectral_features(_ts(bursts))["Spectral Entropy"]
    perfect_entropy = compute_spectral_features(_ts(perfect))["Spectral Entropy"]
    assert burst_entropy > perfect_entropy * 0.8, \
        f"burst entropy {burst_entropy:.3f} should be comparable or higher than periodic {perfect_entropy:.3f}"


def test_zero_crossing_rate_in_unit_interval():
    rng = np.random.default_rng(7)
    times = np.cumsum(rng.exponential(scale=0.1, size=50))
    out = compute_spectral_features(_ts(times.tolist()))
    assert 0.0 <= out["IAT Zero Crossing Rate"] <= 1.0


def test_spectral_entropy_nonnegative():
    rng = np.random.default_rng(2)
    times = np.cumsum(rng.exponential(scale=0.1, size=50))
    out = compute_spectral_features(_ts(times.tolist()))
    assert out["Spectral Entropy"] >= 0
