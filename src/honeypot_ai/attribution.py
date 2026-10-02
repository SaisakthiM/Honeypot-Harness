"""Provenance: link a suspicious tool call back to the untrusted content that
carried the matching values (emails, URLs, paths) but never came from the user."""
from __future__ import annotations

import json
import re

ATOM_RE = re.compile(
    r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"      # emails
    r"|https?://[^\s\"'<>\\)]+"          # urls
    r"|~?/[\w./-]{3,}"                   # paths
)


def _atoms(text: str) -> set:
    return {a.rstrip(".,;") for a in ATOM_RE.findall(text)}


def attribute(args: dict, user_text: str, untrusted: list) -> list:
    blob = json.dumps(args, ensure_ascii=False, default=str)
    candidates = _atoms(blob) - _atoms(user_text)
    out = []
    for src in untrusted:
        matched = sorted(a for a in candidates if a and a in src["text"])
        if matched:
            out.append({"source": src["source"], "step": src["step"], "matched": matched})
    return out
