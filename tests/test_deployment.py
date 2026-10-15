"""NB-09 — the container runs as nobody's root and the default exposure
is the loopback. Text-level guards: the Dockerfile and the compose file
are infrastructure-as-documentation, and these assertions keep the
hardening from regressing silently (a `git revert` shows up here too)."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_dockerfile_runs_as_a_dedicated_non_root_user():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "USER noirebox" in text
    assert "useradd" in text and "10001" in text
    # the user exists AFTER the install steps and BEFORE the runtime
    assert text.index("USER noirebox") > text.index("pip install")
    assert text.index("USER noirebox") < text.index("HEALTHCHECK")


def test_compose_binds_loopback_and_names_the_auth_choice():
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert '"127.0.0.1:8768:8768"' in text  # never all-interfaces by default
    assert "NOIREBOX_CLIENTS" in text       # exposing means configuring auth
