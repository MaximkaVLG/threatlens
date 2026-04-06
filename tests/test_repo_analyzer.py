"""Tests for GitHub repository analyzer."""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from threatlens.analyzers.repo_analyzer import (
    _validate_repo_url, _parse_repo_url, _should_skip, analyze,
)


class TestURLValidation:
    def test_valid_github(self):
        assert _validate_repo_url("https://github.com/user/repo") is None

    def test_valid_gitlab(self):
        assert _validate_repo_url("https://gitlab.com/user/repo") is None

    def test_valid_bitbucket(self):
        assert _validate_repo_url("https://bitbucket.org/user/repo") is None

    def test_reject_http(self):
        err = _validate_repo_url("http://github.com/user/repo")
        assert err is not None
        assert "HTTPS" in err

    def test_reject_localhost(self):
        err = _validate_repo_url("https://localhost/repo")
        assert err is not None
        assert "local" in err.lower() or "not in allowed" in err.lower()

    def test_reject_127(self):
        err = _validate_repo_url("https://127.0.0.1/repo")
        assert err is not None

    def test_reject_unknown_host(self):
        err = _validate_repo_url("https://evil.com/repo")
        assert err is not None
        assert "not in allowed" in err.lower()

    def test_reject_no_scheme(self):
        err = _validate_repo_url("github.com/user/repo")
        assert err is not None

    def test_reject_empty(self):
        err = _validate_repo_url("")
        assert err is not None

    def test_reject_ftp(self):
        err = _validate_repo_url("ftp://github.com/user/repo")
        assert err is not None


class TestParseRepoURL:
    def test_github_url(self):
        assert _parse_repo_url("https://github.com/user/repo") == "user/repo"

    def test_trailing_slash(self):
        assert _parse_repo_url("https://github.com/user/repo/") == "user/repo"

    def test_dot_git(self):
        assert _parse_repo_url("https://github.com/user/repo.git") == "user/repo"


class TestShouldSkip:
    def test_skip_git(self):
        import tempfile, shutil
        d = tempfile.mkdtemp()
        p = os.path.join(d, ".git", "config")
        os.makedirs(os.path.dirname(p))
        open(p, "w").write("x")
        assert _should_skip(p, d)
        shutil.rmtree(d)

    def test_skip_node_modules(self):
        import tempfile, shutil
        d = tempfile.mkdtemp()
        p = os.path.join(d, "node_modules", "pkg", "index.js")
        os.makedirs(os.path.dirname(p))
        open(p, "w").write("x")
        assert _should_skip(p, d)
        shutil.rmtree(d)

    def test_skip_image(self):
        import tempfile
        p = tempfile.mktemp(suffix=".png")
        open(p, "wb").write(b"\x89PNG")
        assert _should_skip(p, os.path.dirname(p))
        os.unlink(p)

    def test_dont_skip_python(self):
        import tempfile
        p = tempfile.mktemp(suffix=".py")
        open(p, "w").write("print(1)")
        assert not _should_skip(p, os.path.dirname(p))
        os.unlink(p)

    def test_skip_large_file(self):
        import tempfile
        p = tempfile.mktemp(suffix=".bin")
        open(p, "wb").write(b"\x00" * (6 * 1024 * 1024))
        assert _should_skip(p, os.path.dirname(p))
        os.unlink(p)


class TestAnalyzeInvalidURL:
    def test_invalid_url_returns_error(self):
        result = analyze("https://evil.com/malware")
        assert result.findings
        assert "Invalid" in result.findings[0] or "not in allowed" in result.findings[0]

    def test_localhost_blocked(self):
        result = analyze("https://localhost/repo")
        assert result.findings
