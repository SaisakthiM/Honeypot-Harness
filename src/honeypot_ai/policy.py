"""Block / observe / allow decisions, made at the tool-call boundary.

The decision never depends on an LLM judging text. It depends on what the agent
actually tries to DO.

  canary_leak       canary credential in tool args            -> block
  decoy_hit         decoy tool called                         -> observe (or block)
  policy_violation  URL host outside the allowlist            -> block
  clean             nothing matched                           -> allow
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from .decoys import Canaries, Tool

URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+")


@dataclass
class Decision:
    action: str    # block | observe | allow
    category: str  # clean | decoy_hit | canary_leak | policy_violation
    reason: str


class Policy:
    def __init__(self, canaries: Canaries, allowed_hosts=(), decoy_action: str = "observe"):
        if decoy_action not in ("observe", "block"):
            raise ValueError("decoy_action must be 'observe' or 'block'")
        self.canaries = canaries
        self.allowed_hosts = set(allowed_hosts)
        self.decoy_action = decoy_action

    def evaluate(self, tool: Tool, args: dict) -> Decision:
        blob = json.dumps(args, ensure_ascii=False, default=str)

        leaked = self.canaries.find_in(blob)
        if leaked:
            return Decision("block", "canary_leak",
                            f"canary credential ({', '.join(leaked)}...) found in arguments of '{tool.name}'")

        if tool.decoy:
            return Decision(self.decoy_action, "decoy_hit",
                            f"decoy tool '{tool.name}' called; this task never needs it")

        for url in URL_RE.findall(blob):
            host = urlparse(url).hostname
            if host and host not in self.allowed_hosts:
                return Decision("block", "policy_violation",
                                f"'{tool.name}' targets host '{host}' outside the allowlist")

        return Decision("allow", "clean", "no rule matched")
