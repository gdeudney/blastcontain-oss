"""Pytest fixtures shared across verify tests."""
import pytest


@pytest.fixture
def clean_env(monkeypatch):
    """Remove common credential env vars so CRED-02 starts clean."""
    keys_to_clear = [
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN", "GH_TOKEN",
        "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AZURE_CLIENT_SECRET",
        "SLACK_TOKEN", "STRIPE_SECRET_KEY",
    ]
    for key in keys_to_clear:
        monkeypatch.delenv(key, raising=False)
    yield
