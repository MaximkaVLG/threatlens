"""Tests for heuristic engine."""

import pytest
from threatlens.scoring.heuristic_engine import analyze as heuristic_analyze
from threatlens.analyzers import generic_analyzer, script_analyzer


class TestHeuristicEngine:
    def test_stealer_detection(self, stealer_script):
        g = generic_analyzer.analyze(stealer_script)
        s = script_analyzer.analyze(stealer_script)
        verdicts = heuristic_analyze(g, None, s, g.findings + s.findings)
        assert verdicts
        assert verdicts[0].threat_type == "stealer"
        assert verdicts[0].confidence >= 0.5

    def test_clean_no_verdict(self, clean_script):
        g = generic_analyzer.analyze(clean_script)
        s = script_analyzer.analyze(clean_script)
        verdicts = heuristic_analyze(g, None, s, g.findings + s.findings)
        assert len(verdicts) == 0

    def test_dropper_detection(self, tmp_file):
        code = (
            "import os, base64\n"
            "exec(base64.b64decode('cHJpbnQoMSsx'))\n"
            "eval(compile(base64.b64decode('cHJpbnQoMSsx').decode(), '<s>', 'exec'))\n"
            "Invoke-Expression 'test'\n"
        )
        p = tmp_file(code.encode(), suffix=".py")
        g = generic_analyzer.analyze(p)
        s = script_analyzer.analyze(p)
        verdicts = heuristic_analyze(g, None, s, g.findings + s.findings)
        types = [v.threat_type for v in verdicts]
        assert "dropper" in types

    def test_keylogger_detection(self, tmp_file):
        code = (
            "from pynput.keyboard import Listener\n"
            "from pynput import keyboard\n"
            "import pyautogui\n"
            "def on_press(key): pass\n"
            "keyboard.on_press = on_press\n"
            "img = pyautogui.screenshot()\n"
            "from ImageGrab import grab\n"
            "ImageGrab.grab().save('s.png')\n"
        )
        p = tmp_file(code.encode(), suffix=".py")
        g = generic_analyzer.analyze(p)
        s = script_analyzer.analyze(p)
        verdicts = heuristic_analyze(g, None, s, g.findings + s.findings)
        types = [v.threat_type for v in verdicts]
        assert "keylogger" in types

    def test_confidence_range(self, stealer_script):
        g = generic_analyzer.analyze(stealer_script)
        s = script_analyzer.analyze(stealer_script)
        verdicts = heuristic_analyze(g, None, s, g.findings + s.findings)
        for v in verdicts:
            assert 0.0 <= v.confidence <= 1.0
