"""Single source of truth for the version is pyproject.toml; read it back from package metadata."""
from __future__ import annotations

try:
    from importlib.metadata import version as _version

    __version__ = _version("honeypot-ai")
except Exception:  # noqa: BLE001  (not installed, e.g. running from a bare checkout)
    __version__ = "0.0.0+unknown"
