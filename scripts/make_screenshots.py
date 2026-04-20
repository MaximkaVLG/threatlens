"""Produce diploma-defense screenshots of the Network IDS dashboard.

Runs the detector on a real CIC-IDS2017 slice, then exports the four Plotly
charts (timeline / class pie / protocol pie / top talkers) plus a SHAP
attribution chart as static PNGs in docs/screenshots/.
"""

from __future__ import annotations

import os
import sys

import numpy as np
import pandas as pd
import plotly.graph_objects as go

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..")))

from threatlens.network import FlowDetector

DATA_CSV = os.path.join(_HERE, "..", "data", "cicids2017",
                        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
RESULTS_DIR = os.path.join(_HERE, "..", "results", "cicids2017")
SCREENSHOT_DIR = os.path.join(_HERE, "..", "docs", "screenshots")

DARK_LAYOUT = dict(
    paper_bgcolor="#111", plot_bgcolor="#111",
    font=dict(color="#cccccc", family="Segoe UI, sans-serif", size=13),
    margin=dict(t=60, r=30, b=50, l=60),
    xaxis=dict(gridcolor="#222", zerolinecolor="#333"),
    yaxis=dict(gridcolor="#222", zerolinecolor="#333"),
)


def write_png(fig: go.Figure, name: str, width: int = 900, height: int = 500):
    path = os.path.join(SCREENSHOT_DIR, name)
    fig.write_image(path, width=width, height=height, format="png")
    print(f"  -> {os.path.relpath(path)}")


def build_dashboard_screenshots(summary: dict):
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    # --- Timeline (stacked bars: benign vs attack) ---------------------------
    tl = summary["timeline"]
    if len(tl) > 1:
        xs = [pd.to_datetime(b["timestamp"], unit="s") for b in tl]
        benign = [b["benign"] for b in tl]
        attack = [b["attack"] for b in tl]
        fig = go.Figure([
            go.Bar(x=xs, y=benign, name="Безопасные", marker_color="#4caf50"),
            go.Bar(x=xs, y=attack, name="Атаки", marker_color="#f44336"),
        ])
        fig.update_layout(
            title=dict(text="Поток потоков во времени", font=dict(color="#00d4ff", size=16)),
            barmode="stack",
            xaxis=dict(title="Время", gridcolor="#222"),
            yaxis=dict(title="Потоков / бакет", gridcolor="#222"),
            legend=dict(bgcolor="#111", bordercolor="#333"),
            **{k: v for k, v in DARK_LAYOUT.items() if k not in ("xaxis", "yaxis")},
        )
        write_png(fig, "network_timeline.png")

    # --- Class distribution pie ---------------------------------------------
    labels = list(summary["labels"].items())
    if labels:
        colors = ["#4caf50" if k == "BENIGN" else "#f44336" for k, _ in labels]
        fig = go.Figure([go.Pie(
            labels=[k for k, _ in labels], values=[v for _, v in labels],
            hole=0.45, marker=dict(colors=colors), textinfo="label+percent",
        )])
        fig.update_layout(
            title=dict(text="Распределение классов", font=dict(color="#00d4ff", size=16)),
            showlegend=False,
            **{k: v for k, v in DARK_LAYOUT.items() if k not in ("xaxis", "yaxis")},
        )
        write_png(fig, "network_labels_pie.png", width=700, height=500)

    # --- Top talkers stacked bar --------------------------------------------
    talkers = summary["top_talkers"][:8]
    if talkers:
        names = [t["src_ip"] for t in talkers]
        attacks = [t.get("attacks", 0) for t in talkers]
        benign = [max(0, t.get("flows", 0) - t.get("attacks", 0)) for t in talkers]
        fig = go.Figure([
            go.Bar(y=names, x=benign, name="Безопасные", orientation="h", marker_color="#4caf50"),
            go.Bar(y=names, x=attacks, name="Атаки", orientation="h", marker_color="#f44336"),
        ])
        fig.update_layout(
            title=dict(text="Топ источников трафика", font=dict(color="#00d4ff", size=16)),
            barmode="stack",
            xaxis=dict(title="Потоков", gridcolor="#222"),
            yaxis=dict(automargin=True, gridcolor="#222"),
            legend=dict(bgcolor="#111", bordercolor="#333"),
            **{k: v for k, v in DARK_LAYOUT.items() if k not in ("xaxis", "yaxis")},
        )
        write_png(fig, "network_top_talkers.png", width=900, height=450)


def build_shap_screenshot(detector: FlowDetector, sample_flow: dict):
    explanation = detector.explain_shap(sample_flow, top_k=10)
    contribs = list(reversed(explanation["contributions"]))  # smallest at bottom
    names = [c["feature"] for c in contribs]
    vals = [c["shap_value"] for c in contribs]
    raw = [c["feature_value"] for c in contribs]
    colors = ["#f44336" if v >= 0 else "#00d4ff" for v in vals]
    hover = [f"SHAP {v:+.3f}<br>value {r:.2f}" for v, r in zip(vals, raw)]

    fig = go.Figure([go.Bar(
        y=names, x=vals, orientation="h",
        marker_color=colors, text=hover, hoverinfo="y+text",
    )])
    fig.update_layout(
        title=dict(
            text=f"SHAP: вклад фич в предсказание '{explanation['predicted_class']}'",
            font=dict(color="#9c27b0", size=16),
        ),
        xaxis=dict(title="SHAP value", gridcolor="#222",
                   zeroline=True, zerolinecolor="#555", zerolinewidth=2),
        yaxis=dict(automargin=True, gridcolor="#222"),
        **{k: v for k, v in DARK_LAYOUT.items() if k not in ("xaxis", "yaxis")},
    )
    write_png(fig, "network_shap.png", width=900, height=500)


def main():
    if not os.path.exists(DATA_CSV):
        print(f"CIC-IDS2017 CSV not found: {DATA_CSV}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(os.path.join(RESULTS_DIR, "xgboost.joblib")):
        print(f"Trained models missing in {RESULTS_DIR}", file=sys.stderr)
        sys.exit(1)

    print("Reading CIC-IDS2017 slice...")
    df = pd.read_csv(DATA_CSV, nrows=80000, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    df = df.replace([np.inf, -np.inf], np.nan).dropna(
        subset=df.select_dtypes(include=[np.number]).columns
    )
    sample = df.sample(2500, random_state=42)

    # Synthesize required metadata columns so detector.summary() can bucket
    # by protocol / timeline / src_ip. CIC-IDS2017 CSVs don't ship IPs; we
    # emit anchor IPs that preserve the attack/benign structure for display.
    sample = sample.copy()
    rng = np.random.default_rng(42)
    attacker_pool = [f"10.10.10.{i}" for i in range(60, 70)]
    victim_pool = [f"192.168.1.{i}" for i in range(40, 60)]
    def _src(row):
        return (rng.choice(attacker_pool) if row["Label"] != "BENIGN"
                else rng.choice(victim_pool))
    sample["src_ip"] = sample.apply(_src, axis=1)
    sample["dst_ip"] = [rng.choice(victim_pool) for _ in range(len(sample))]
    sample["src_port"] = rng.integers(1024, 65535, size=len(sample))
    sample["protocol"] = rng.choice([6, 17], size=len(sample), p=[0.9, 0.1])
    base_ts = 1_700_000_000.0
    sample["timestamp"] = base_ts + np.arange(len(sample)) * 0.05

    print("Loading detector...")
    detector = FlowDetector.from_results_dir(RESULTS_DIR)
    print("Predicting...")
    predictions = detector.predict(sample, model="xgboost")
    summary = detector.summary(predictions)
    print(f"  total flows: {summary['total_flows']}, attacks: {summary['attack_flows']}")

    print("Building dashboard screenshots...")
    build_dashboard_screenshots(summary)

    print("Building SHAP screenshot on a PortScan row...")
    portscan = sample[sample["Label"] == "PortScan"].iloc[0].to_dict()
    build_shap_screenshot(detector, portscan)

    print("\nDone. Screenshots in docs/screenshots/")


if __name__ == "__main__":
    main()
