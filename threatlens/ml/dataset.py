"""CIC-IDS2017 dataset loader.

The CIC-IDS2017 dataset contains 8 CSV files with ~2.8M flow records:
    - Monday-WorkingHours.pcap_ISCX.csv           (BENIGN only, baseline)
    - Tuesday-WorkingHours.pcap_ISCX.csv          (FTP-Patator, SSH-Patator)
    - Wednesday-workingHours.pcap_ISCX.csv        (DoS attacks: slowloris, Hulk, GoldenEye, Slowhttptest, Heartbleed)
    - Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv  (XSS, SQL Injection, Brute Force)
    - Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv (Infiltration)
    - Friday-WorkingHours-Morning.pcap_ISCX.csv   (Bot)
    - Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv  (PortScan)
    - Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv  (DDoS)

Each row has 78 flow-based features + 1 Label column.

Download: https://www.unb.ca/cic/datasets/ids-2017.html (requires free registration)
Alternative: Kaggle mirror https://www.kaggle.com/datasets/cicdataset/cicids2017
"""

import os
import glob
import logging
from typing import Optional, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Top 20 most predictive flow features (per CIC-IDS2017 research)
# Full list of 78 features is available after loading
SAMPLE_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Max",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Fwd PSH Flags",
    "SYN Flag Count",
    "ACK Flag Count",
    "Packet Length Mean",
    "Packet Length Std",
]

# Attack categories in CIC-IDS2017
ATTACK_CATEGORIES = {
    "BENIGN": "benign",
    "DoS Hulk": "dos",
    "DoS GoldenEye": "dos",
    "DoS slowloris": "dos",
    "DoS Slowhttptest": "dos",
    "Heartbleed": "dos",
    "DDoS": "ddos",
    "PortScan": "portscan",
    "FTP-Patator": "bruteforce",
    "SSH-Patator": "bruteforce",
    "Web Attack – Brute Force": "webattack",
    "Web Attack  Brute Force": "webattack",  # alt encoding
    "Web Attack – XSS": "webattack",
    "Web Attack  XSS": "webattack",
    "Web Attack – Sql Injection": "webattack",
    "Web Attack  Sql Injection": "webattack",
    "Bot": "botnet",
    "Infiltration": "infiltration",
}


def _clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """CIC-IDS2017 CSVs have leading spaces in column names — strip them."""
    df.columns = [c.strip() for c in df.columns]
    return df


def _map_labels(df: pd.DataFrame, label_col: str = "Label") -> pd.DataFrame:
    """Map granular attack names to high-level categories."""
    if label_col not in df.columns:
        raise ValueError(f"Label column '{label_col}' not found. Columns: {list(df.columns)[:5]}...")
    df[label_col] = df[label_col].str.strip()
    df["category"] = df[label_col].map(lambda x: ATTACK_CATEGORIES.get(x, "unknown"))
    # Binary label: 0 = benign, 1 = attack
    df["is_attack"] = (df[label_col] != "BENIGN").astype(int)
    return df


def load_cicids2017(
    data_dir: str,
    sample_size: Optional[int] = None,
    balance: bool = False,
    random_state: int = 42,
) -> pd.DataFrame:
    """Load and concatenate all CIC-IDS2017 CSV files.

    Args:
        data_dir: Directory containing the 8 CIC-IDS2017 CSV files
        sample_size: If given, randomly sample this many rows (useful for dev)
        balance: If True, balance classes (oversample minority attacks or downsample BENIGN)
        random_state: Random seed for reproducibility

    Returns:
        DataFrame with 78 features + Label + category + is_attack columns

    Raises:
        FileNotFoundError: If no CSV files found in data_dir
    """
    csv_files = sorted(glob.glob(os.path.join(data_dir, "*.csv")))
    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {data_dir!r}. "
            f"Download CIC-IDS2017 from https://www.unb.ca/cic/datasets/ids-2017.html"
        )

    logger.info("Loading %d CSV files from %s", len(csv_files), data_dir)

    dfs = []
    for csv_path in csv_files:
        logger.info("Reading %s", os.path.basename(csv_path))
        try:
            df = pd.read_csv(csv_path, low_memory=False, encoding="utf-8")
        except UnicodeDecodeError:
            df = pd.read_csv(csv_path, low_memory=False, encoding="latin-1")
        df = _clean_column_names(df)
        dfs.append(df)

    df = pd.concat(dfs, ignore_index=True)
    logger.info("Total rows loaded: %d", len(df))

    # Clean: drop rows with NaN or infinite values in numeric columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df = df.replace([np.inf, -np.inf], np.nan)
    initial = len(df)
    df = df.dropna(subset=numeric_cols)
    logger.info("Dropped %d rows with NaN/inf values", initial - len(df))

    df = _map_labels(df)

    if sample_size and sample_size < len(df):
        # Stratified sample preserving class distribution (manual to avoid
        # pandas 2.x groupby().apply() dropping group keys)
        sampled_parts = []
        total = len(df)
        for label, group in df.groupby("Label"):
            n_take = min(len(group), max(1, int(sample_size * len(group) / total)))
            sampled_parts.append(group.sample(n=n_take, random_state=random_state))
        df = pd.concat(sampled_parts, ignore_index=True)
        logger.info("Sampled %d rows", len(df))

    if balance:
        df = _balance_classes(df, random_state=random_state)

    return df.reset_index(drop=True)


def _balance_classes(df: pd.DataFrame, random_state: int = 42) -> pd.DataFrame:
    """Downsample majority class (BENIGN) to median class size."""
    class_sizes = df["Label"].value_counts()
    median_size = int(class_sizes.median())

    balanced = []
    for label, size in class_sizes.items():
        subset = df[df["Label"] == label]
        if size > median_size:
            subset = subset.sample(n=median_size, random_state=random_state)
        balanced.append(subset)

    return pd.concat(balanced, ignore_index=True)


def load_synthetic(n_samples: int = 10000, random_state: int = 42) -> pd.DataFrame:
    """Generate synthetic CIC-IDS2017-style data for pipeline validation.

    Used when real dataset is not yet downloaded. Creates realistic feature
    distributions for BENIGN, DoS, PortScan, and BruteForce classes.
    """
    rng = np.random.default_rng(random_state)

    # Class proportions similar to CIC-IDS2017
    class_probs = {
        "BENIGN": 0.80,
        "DoS Hulk": 0.08,
        "PortScan": 0.06,
        "DDoS": 0.03,
        "FTP-Patator": 0.02,
        "Bot": 0.01,
    }

    n_per_class = {k: max(10, int(n_samples * v)) for k, v in class_probs.items()}

    rows = []
    for label, n in n_per_class.items():
        # Different feature distributions per attack type
        if label == "BENIGN":
            data = {
                "Flow Duration": rng.exponential(1e6, n),
                "Total Fwd Packets": rng.poisson(10, n),
                "Total Backward Packets": rng.poisson(8, n),
                "Total Length of Fwd Packets": rng.exponential(5000, n),
                "Total Length of Bwd Packets": rng.exponential(4000, n),
                "Flow Bytes/s": rng.exponential(1e4, n),
                "Flow Packets/s": rng.exponential(50, n),
                "SYN Flag Count": rng.binomial(2, 0.3, n),
                "ACK Flag Count": rng.poisson(5, n),
                "Packet Length Mean": rng.normal(500, 200, n).clip(0),
            }
        elif "DoS" in label or label == "DDoS":
            # DoS: many packets, high rate, short flows
            data = {
                "Flow Duration": rng.exponential(1e5, n),
                "Total Fwd Packets": rng.poisson(500, n),
                "Total Backward Packets": rng.poisson(5, n),
                "Total Length of Fwd Packets": rng.exponential(500, n),
                "Total Length of Bwd Packets": rng.exponential(100, n),
                "Flow Bytes/s": rng.exponential(1e6, n),
                "Flow Packets/s": rng.exponential(5000, n),
                "SYN Flag Count": rng.poisson(50, n),
                "ACK Flag Count": rng.poisson(2, n),
                "Packet Length Mean": rng.normal(60, 10, n).clip(0),
            }
        elif label == "PortScan":
            # PortScan: many short flows, few packets each
            data = {
                "Flow Duration": rng.exponential(1e3, n),
                "Total Fwd Packets": rng.poisson(2, n),
                "Total Backward Packets": rng.poisson(1, n),
                "Total Length of Fwd Packets": rng.exponential(100, n),
                "Total Length of Bwd Packets": rng.exponential(50, n),
                "Flow Bytes/s": rng.exponential(1e3, n),
                "Flow Packets/s": rng.exponential(100, n),
                "SYN Flag Count": rng.binomial(2, 0.9, n),
                "ACK Flag Count": rng.binomial(2, 0.5, n),
                "Packet Length Mean": rng.normal(40, 20, n).clip(0),
            }
        elif "Patator" in label:
            # Brute force: moderate flows, distinctive pattern
            data = {
                "Flow Duration": rng.exponential(5e5, n),
                "Total Fwd Packets": rng.poisson(20, n),
                "Total Backward Packets": rng.poisson(15, n),
                "Total Length of Fwd Packets": rng.exponential(1000, n),
                "Total Length of Bwd Packets": rng.exponential(2000, n),
                "Flow Bytes/s": rng.exponential(5e3, n),
                "Flow Packets/s": rng.exponential(10, n),
                "SYN Flag Count": rng.binomial(2, 0.5, n),
                "ACK Flag Count": rng.poisson(10, n),
                "Packet Length Mean": rng.normal(300, 100, n).clip(0),
            }
        else:  # Bot
            data = {
                "Flow Duration": rng.exponential(2e6, n),
                "Total Fwd Packets": rng.poisson(30, n),
                "Total Backward Packets": rng.poisson(25, n),
                "Total Length of Fwd Packets": rng.exponential(3000, n),
                "Total Length of Bwd Packets": rng.exponential(2500, n),
                "Flow Bytes/s": rng.exponential(5e3, n),
                "Flow Packets/s": rng.exponential(20, n),
                "SYN Flag Count": rng.binomial(2, 0.4, n),
                "ACK Flag Count": rng.poisson(15, n),
                "Packet Length Mean": rng.normal(200, 100, n).clip(0),
            }

        df_class = pd.DataFrame(data)
        df_class["Label"] = label
        rows.append(df_class)

    df = pd.concat(rows, ignore_index=True).sample(frac=1, random_state=random_state).reset_index(drop=True)
    df = _map_labels(df)

    return df


def split_features_labels(
    df: pd.DataFrame,
    label_col: str = "Label",
    feature_cols: Optional[list] = None,
) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    """Split DataFrame into X (features), y_multi (multi-class), y_binary (attack/benign)."""
    exclude = {label_col, "category", "is_attack"}
    if feature_cols is None:
        feature_cols = [c for c in df.columns if c not in exclude]
    X = df[feature_cols].select_dtypes(include=[np.number])
    y_multi = df[label_col]
    y_binary = df["is_attack"]
    return X, y_multi, y_binary
