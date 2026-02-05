"""Tests for AI incident module: is_ai_configured, get_ai_status, key loading."""
import os
import sys

# When run as script (no pytest), add project root and run basic checks
if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from modules import ai_incident
    orig_anthropic = os.environ.get("ANTHROPIC_API_KEY")
    orig_openai = os.environ.get("OPENAI_API_KEY")
    try:
        os.environ.pop("ANTHROPIC_API_KEY", None)
        os.environ.pop("OPENAI_API_KEY", None)
        assert not ai_incident.is_ai_configured()
        assert ai_incident.get_ai_status() == "Not configured"
        print("OK: No keys -> Not configured")
        os.environ["OPENAI_API_KEY"] = "sk-dummy"
        assert ai_incident.is_ai_configured()
        assert ai_incident.get_ai_status() == "OpenAI"
        print("OK: OPENAI_API_KEY set -> OpenAI")
    finally:
        if orig_anthropic is not None:
            os.environ["ANTHROPIC_API_KEY"] = orig_anthropic
        if orig_openai is not None:
            os.environ["OPENAI_API_KEY"] = orig_openai
        else:
            os.environ.pop("OPENAI_API_KEY", None)
    print("All AI incident checks passed.")
    sys.exit(0)

import pytest


def test_is_ai_configured_false_when_no_keys(monkeypatch):
    """When neither key is set, is_ai_configured is False."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    from modules import ai_incident
    assert ai_incident.is_ai_configured() is False
    assert ai_incident.get_ai_status() == "Not configured"


def test_is_ai_configured_true_with_openai(monkeypatch):
    """When OPENAI_API_KEY is set, is_ai_configured is True and status is OpenAI."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-dummy")
    from modules import ai_incident
    assert ai_incident.is_ai_configured() is True
    assert ai_incident.get_ai_status() == "OpenAI"


def test_is_ai_configured_true_with_anthropic(monkeypatch):
    """When ANTHROPIC_API_KEY is set, is_ai_configured is True and status is Anthropic."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-dummy")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    from modules import ai_incident
    assert ai_incident.is_ai_configured() is True
    assert ai_incident.get_ai_status() == "Anthropic"


def test_parse_incident_returns_none_when_not_configured(monkeypatch):
    """parse_incident_description returns None when no API key is set."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    from modules import ai_incident
    assert ai_incident.parse_incident_description("Slide 45 mislabeled.") is None
