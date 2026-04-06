"""Profile ThreatLens scan performance to find bottlenecks."""

import time
import sys
import os
import random
import string

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def create_test_file(size_kb=18000):
    """Create realistic test file with strings, URLs, paths."""
    path = os.path.join(os.path.dirname(__file__), "samples", "test_perf.bin")
    os.makedirs(os.path.dirname(path), exist_ok=True)

    data = bytearray(b"MZ\x90\x00" + b"\x00" * 60)
    target_size = size_kb * 1024

    while len(data) < target_size:
        # Random bytes
        data.extend(bytes(random.randint(0, 255) for _ in range(200)))
        # Readable strings
        data.extend("".join(random.choices(string.ascii_letters, k=40)).encode())
        data.extend(b"\x00")
        # URLs
        data.extend(f"http://example{random.randint(1,999)}.com/file.exe\x00".encode())
        # Paths
        data.extend(f"C:\\Users\\test\\AppData\\Local\\file{random.randint(1,999)}.dat\x00".encode())

    with open(path, "wb") as f:
        f.write(bytes(data[:target_size]))

    print(f"Created test file: {os.path.getsize(path) // 1024} KB")
    return path


def profile(path):
    """Profile each analysis step."""
    from threatlens.analyzers import generic_analyzer, pe_analyzer
    from threatlens.rules.signatures import scan as yara_scan
    from threatlens.scoring.threat_scorer import calculate_score
    from threatlens.scoring.heuristic_engine import analyze as heuristic_analyze
    from threatlens.ai.explanations import generate_explanation

    # Step 1: Generic
    t = time.time()
    generic = generic_analyzer.analyze(path)
    t_generic = time.time() - t

    # Step 2: PE
    t = time.time()
    pe = pe_analyzer.analyze(path)
    t_pe = time.time() - t

    # Step 3: YARA
    t = time.time()
    yara_result = yara_scan(path)
    t_yara = time.time() - t

    # Step 4: Heuristic
    findings = list(generic.findings) + list(pe.findings) + list(yara_result.findings)
    t = time.time()
    heuristic = heuristic_analyze(generic, pe, None, findings)
    t_heuristic = time.time() - t

    # Step 5: Scoring + explanation
    t = time.time()
    score = calculate_score(findings, generic, pe, None)
    explanation = generate_explanation(score.categories)
    t_scoring = time.time() - t

    total = t_generic + t_pe + t_yara + t_heuristic + t_scoring

    print(f"\n{'='*50}")
    print(f"{'Step':<25s} {'Time':>8s} {'%':>6s}")
    print(f"{'='*50}")
    for name, dur in [
        ("Generic analysis", t_generic),
        ("PE analysis", t_pe),
        ("YARA scan", t_yara),
        ("Heuristic engine", t_heuristic),
        ("Scoring + explanation", t_scoring),
    ]:
        pct = dur / total * 100 if total > 0 else 0
        bar = "#" * int(pct / 2)
        print(f"  {name:<23s} {dur:>6.2f}s {pct:>5.1f}% {bar}")
    print(f"{'='*50}")
    print(f"  {'TOTAL':<23s} {total:>6.2f}s")
    print(f"\n  Findings: {len(findings)}")
    print(f"  URLs: {len(generic.urls)}")
    print(f"  IPs: {len(generic.ip_addresses)}")
    print(f"  YARA matches: {len(yara_result.matches)}")


if __name__ == "__main__":
    size = int(sys.argv[1]) if len(sys.argv) > 1 else 18000
    path = create_test_file(size)
    profile(path)
