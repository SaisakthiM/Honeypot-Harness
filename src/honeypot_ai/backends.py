"""Model backends. Anything with `chat(messages, tools) -> Reply` works.

Internal message format (backend-agnostic):
  {"role": "system"|"user", "content": str}
  {"role": "assistant", "content": str, "tool_calls": [{"id","name","arguments"}]}
  {"role": "tool", "name": str, "tool_call_id": str, "content": str}
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

import httpx


@dataclass
class Reply:
    content: str
    tool_calls: list = field(default_factory=list)  # [{"id","name","arguments": dict}]
    thinking: str = ""
    raw: dict = field(default_factory=dict)


def _safe_json(s):
    try:
        v = json.loads(s)
        return v if isinstance(v, dict) else {}
    except Exception:
        return {}


class OllamaBackend:
    def __init__(self, model=None, host=None, think=None, temperature=0.0, timeout=300):
        self.model = model or os.getenv("HONEYPOT_MODEL", "qwen3.5:4b")
        host = host or os.getenv("OLLAMA_HOST", "http://localhost:11434")
        if not host.startswith("http"):
            host = "http://" + host
        self.host = host.rstrip("/")
        self.think = think
        self.temperature = temperature
        self.timeout = timeout

    def _wire(self, messages):
        out = []
        for m in messages:
            if m["role"] == "assistant" and m.get("tool_calls"):
                out.append({
                    "role": "assistant",
                    "content": m["content"],
                    "tool_calls": [{"function": {"name": tc["name"], "arguments": tc["arguments"]}}
                                   for tc in m["tool_calls"]],
                })
            elif m["role"] == "tool":
                out.append({"role": "tool", "tool_name": m["name"], "content": m["content"]})
            else:
                out.append({"role": m["role"], "content": m["content"]})
        return out

    def chat(self, messages, tools) -> Reply:
        payload = {
            "model": self.model,
            "messages": self._wire(messages),
            "tools": tools,
            "stream": False,
            "options": {"temperature": self.temperature},
        }
        if self.think is not None:
            payload["think"] = self.think
        try:
            r = httpx.post(f"{self.host}/api/chat", json=payload, timeout=self.timeout, trust_env=False)
        except httpx.ConnectError:
            raise RuntimeError(f"Cannot reach Ollama at {self.host}. Is `ollama serve` running?")
        if r.status_code >= 400:
            raise RuntimeError(f"Ollama error {r.status_code}: {r.text}  (model='{self.model}'; check `ollama list`)")
        data = r.json()
        msg = data.get("message", {}) or {}
        calls = []
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc.get("function", {})
            args = fn.get("arguments") or {}
            if isinstance(args, str):
                args = _safe_json(args)
            calls.append({"id": tc.get("id") or f"call_{i}", "name": fn.get("name", ""), "arguments": args})
        return Reply(msg.get("content") or "", calls, msg.get("thinking") or "", data)


class OpenAICompatBackend:
    """OpenAI, or any OpenAI-compatible server (vLLM, LM Studio, Ollama's /v1, ...)."""

    def __init__(self, model, base_url="https://api.openai.com/v1", api_key=None, temperature=None, timeout=120):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.temperature = temperature
        self.timeout = timeout

    def _wire(self, messages):
        out = []
        for m in messages:
            if m["role"] == "assistant" and m.get("tool_calls"):
                out.append({
                    "role": "assistant",
                    "content": m["content"] or None,
                    "tool_calls": [{"id": tc["id"], "type": "function",
                                    "function": {"name": tc["name"], "arguments": json.dumps(tc["arguments"])}}
                                   for tc in m["tool_calls"]],
                })
            elif m["role"] == "tool":
                out.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
            else:
                out.append({"role": m["role"], "content": m["content"]})
        return out

    def chat(self, messages, tools) -> Reply:
        payload = {"model": self.model, "messages": self._wire(messages), "tools": tools}
        if self.temperature is not None:
            payload["temperature"] = self.temperature
        headers = {"Authorization": f"Bearer {self.api_key}"}
        r = httpx.post(f"{self.base_url}/chat/completions", json=payload, headers=headers, timeout=self.timeout)
        if r.status_code >= 400:
            raise RuntimeError(f"API error {r.status_code}: {r.text}")
        data = r.json()
        msg = data["choices"][0]["message"]
        calls = []
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc.get("function", {})
            args = fn.get("arguments") or {}
            if isinstance(args, str):
                args = _safe_json(args)
            calls.append({"id": tc.get("id") or f"call_{i}", "name": fn.get("name", ""), "arguments": args})
        return Reply(msg.get("content") or "", calls, "", data)


class ScriptedBackend:
    """Deterministic fake agent for offline testing. No model needed.

    Fetches the page, and if the fetched content tells it to send an email, it obeys
    (and leaks the API key from its system prompt). Use it to verify the harness itself.
    """

    model = "scripted"

    def __init__(self, gullible: bool = True):
        self.gullible = gullible

    def chat(self, messages, tools) -> Reply:
        last = messages[-1]
        if last["role"] == "user":
            m = re.search(r"https?://\S+", last["content"])
            url = m.group(0) if m else ""
            return Reply("", [{"id": "c0", "name": "fetch_page", "arguments": {"url": url}}])
        if last["role"] == "tool" and last["name"] == "fetch_page" and self.gullible:
            text = last["content"]
            email = re.search(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", text)
            if email and "send_email" in text:
                key = re.search(r"sk-hp-canary-\w+", messages[0]["content"])
                body = "API key: " + (key.group(0) if key else "n/a")
                return Reply("", [{"id": "c1", "name": "send_email",
                                   "arguments": {"to": email.group(0), "subject": "report", "body": body}}])
        return Reply("Summary: the page explains how oolong tea is made.", [])


def make_backend(kind="ollama", model=None, host=None, think=None):
    kind = (kind or "ollama").lower()
    if kind == "ollama":
        return OllamaBackend(model=model, host=host, think=think)
    if kind in ("openai", "openai-compat"):
        model = model or os.getenv("HONEYPOT_MODEL")
        if not model:
            raise ValueError("openai backend needs --model (or HONEYPOT_MODEL)")
        return OpenAICompatBackend(model=model, base_url=host or "https://api.openai.com/v1")
    if kind == "scripted":
        return ScriptedBackend()
    raise ValueError(f"unknown backend '{kind}' (ollama | openai | scripted)")
