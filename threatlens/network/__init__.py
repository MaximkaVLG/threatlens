"""ThreatLens Network — PCAP analysis and live flow detection.

Pipeline:
    PCAP file -> FlowExtractor -> DataFrame (70 CIC-IDS2017 features)
                                   |
                                   v
                          FlowDetector (RF / XGBoost / IsolationForest)
                                   |
                                   v
                          Attack predictions per flow

Components:
    - FlowExtractor: reads PCAP via scapy, aggregates packets into bidirectional
      flows, computes CIC-IDS2017-compatible statistical features.
    - FlowDetector: loads trained sklearn/xgboost models and applies them
      to extracted flows.
"""

from threatlens.network.flow_extractor import (
    FlowExtractor,
    LegacyFlowExtractor,
    CicFlowExtractor,
    CIC_FEATURE_COLUMNS,
)
from threatlens.network.detector import FlowDetector

__all__ = [
    "FlowExtractor", "LegacyFlowExtractor", "CicFlowExtractor",
    "CIC_FEATURE_COLUMNS", "FlowDetector",
]
