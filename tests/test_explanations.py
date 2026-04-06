"""Tests for built-in threat explanations."""

from threatlens.ai.explanations import generate_explanation


class TestExplanations:
    def test_stealer_ru(self):
        text = generate_explanation({"password_theft": 25, "data_exfiltration": 20}, lang="ru")
        assert len(text) > 20
        # Should detect combined stealer pattern
        assert "Стилер" in text or "паролей" in text.lower()

    def test_stealer_en(self):
        text = generate_explanation({"password_theft": 25, "data_exfiltration": 20}, lang="en")
        assert "stealer" in text.lower() or "password" in text.lower()

    def test_rat_ru(self):
        text = generate_explanation({"injection": 30, "network": 20, "persistence": 15}, lang="ru")
        assert "RAT" in text or "троян" in text.lower() or "код" in text.lower()

    def test_clean_ru(self):
        text = generate_explanation({}, lang="ru")
        assert "безопасн" in text.lower() or "не обнаружен" in text.lower()

    def test_clean_en(self):
        text = generate_explanation({}, lang="en")
        assert "safe" in text.lower() or "no suspicious" in text.lower()

    def test_single_category(self):
        text = generate_explanation({"keylogger": 30}, lang="ru")
        assert len(text) > 20
        assert "клавиатур" in text.lower() or "keylogger" in text.lower()

    def test_unknown_category(self):
        text = generate_explanation({"unknown_thing": 10}, lang="ru")
        # Should not crash, return generic message
        assert len(text) > 0
