"""Run heuristic engine on calibration samples and adjust weights.

Compares heuristic verdicts against ground truth and reports accuracy.
"""

import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from tests.calibration.generate_samples import GROUND_TRUTH, SAMPLES_DIR
from threatlens.core import analyze_file


def run_calibration():
    # Generate samples first
    import tests.calibration.generate_samples

    print("=" * 70)
    print("  ThreatLens Heuristic Calibration")
    print("=" * 70)

    results = []
    correct = 0
    total = len(GROUND_TRUTH)

    for name, expected_type, expected_min_conf in GROUND_TRUTH:
        path = os.path.join(SAMPLES_DIR, name)
        if not os.path.exists(path):
            print(f"  SKIP: {name} (not found)")
            continue

        result = analyze_file(path)

        # Get top heuristic verdict
        actual_type = "clean"
        actual_conf = 0.0

        if result.heuristic_verdicts:
            top = result.heuristic_verdicts[0]
            actual_type = top.threat_type
            actual_conf = top.confidence

        # Check correctness
        is_correct = False
        if expected_type == "clean":
            # Clean file should have no high-confidence verdicts
            is_correct = actual_conf < 0.40 or result.risk_score < 30
        else:
            # Malicious: type should match and confidence >= expected minimum
            is_correct = actual_type == expected_type and actual_conf >= expected_min_conf

        if is_correct:
            correct += 1
            status = "OK"
        else:
            status = "MISS"

        results.append({
            "file": name,
            "expected_type": expected_type,
            "expected_min_conf": expected_min_conf,
            "actual_type": actual_type,
            "actual_conf": actual_conf,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "correct": is_correct,
        })

        conf_str = f"{actual_conf:.0%}" if actual_conf > 0 else "---"
        print(f"  [{status:4s}] {name:30s} expected={expected_type:10s} got={actual_type:10s} conf={conf_str:>5s} score={result.risk_score:3d}")

    # Summary
    accuracy = correct / total if total > 0 else 0
    print("\n" + "=" * 70)
    print(f"  Accuracy: {correct}/{total} ({accuracy:.0%})")
    print("=" * 70)

    # Detailed failures
    failures = [r for r in results if not r["correct"]]
    if failures:
        print("\n  FAILURES:")
        for f in failures:
            print(f"    {f['file']}: expected {f['expected_type']} ({f['expected_min_conf']:.0%}), "
                  f"got {f['actual_type']} ({f['actual_conf']:.0%}), score={f['risk_score']}")

    # Save results
    out_path = os.path.join(os.path.dirname(__file__), "calibration_results.json")
    with open(out_path, "w") as fout:
        json.dump(results, fout, indent=2)
    print(f"\n  Results saved: {out_path}")

    return accuracy, results


if __name__ == "__main__":
    run_calibration()
