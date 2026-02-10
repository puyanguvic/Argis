import json
import subprocess

import phish_email_detection_agent.tools.url_analysis as url_analysis
from phish_email_detection_agent.tools.url_analysis import (
    SafeFetchPolicy,
    analyze_html_content,
    safe_fetch_url,
)


def test_safe_fetch_private_network_blocked():
    result = safe_fetch_url("http://127.0.0.1/login", policy=SafeFetchPolicy(enabled=True))
    assert result["status"] == "blocked"
    assert result["blocked_reason"] == "private_network_blocked"


def test_safe_fetch_disabled_by_default():
    result = safe_fetch_url("https://example.com", policy=SafeFetchPolicy(enabled=False))
    assert result["status"] == "skipped"
    assert result["blocked_reason"] == "network_fetch_disabled"


def test_html_analysis_detects_login_indicators():
    html = """
    <html><body>
      <h1>Microsoft Security Check</h1>
      <form><input type="email"/><input type="password"/></form>
      <script src="https://cdn.example.com/a.js"></script>
      <iframe src="https://cdn.example.com/f.html"></iframe>
      <p>Please verify account urgently</p>
    </body></html>
    """
    report = analyze_html_content(html)
    assert report["password_fields"] == 1
    assert report["login_forms"] >= 1
    assert report["impersonation_score"] >= 40


def test_safe_fetch_firejail_backend_uses_worker(monkeypatch):
    monkeypatch.setattr(url_analysis, "_check_network_target", lambda _url, _allow: (True, None))

    def fake_run(*args, **kwargs):
        payload = {"url": "https://example.com", "status": "ok", "status_code": 200, "html": ""}
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(url_analysis.subprocess, "run", fake_run)
    result = safe_fetch_url(
        "https://example.com",
        policy=SafeFetchPolicy(enabled=True, sandbox_backend="firejail"),
    )
    assert result["status"] == "ok"
    assert result["sandbox_backend"] == "firejail"


def test_safe_fetch_docker_backend_handles_missing_binary(monkeypatch):
    monkeypatch.setattr(url_analysis, "_check_network_target", lambda _url, _allow: (True, None))

    def fake_run(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(url_analysis.subprocess, "run", fake_run)
    result = safe_fetch_url(
        "https://example.com",
        policy=SafeFetchPolicy(enabled=True, sandbox_backend="docker"),
    )
    assert result["status"] == "sandbox_error"
    assert result["blocked_reason"] == "sandbox_backend_unavailable"
