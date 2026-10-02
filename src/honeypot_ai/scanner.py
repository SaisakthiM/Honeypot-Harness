"""Scan HTML for hidden prompt-injection content.

Two layers:

  static    parses the HTML itself: inline styles, <style> rules (simple selectors), the
            `hidden` attribute, <noscript>/<template>, comments, alt/aria/title attributes,
            <meta>, JSON-LD, hidden inputs, Unicode tag characters and zero-width characters.
  rendered  (optional) asks a real browser through Selenium which text nodes are in the DOM
            but not visible. Catches hiding done by external CSS or JavaScript.

Every piece of hidden text is then checked for injection-like language (instructions aimed at
an AI, requests to conceal things from the user, exfiltration verbs next to secrets, pipe-to-shell
...). Severity combines "how was it hidden" with "what does it say". This is a heuristic scanner:
treat findings as leads for a human to review, not as proof.
"""
from __future__ import annotations

import json
import re
import time
import unicodedata
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from typing import List, Optional, Tuple

import httpx

from ._version import __version__

SEVERITIES = ("info", "low", "medium", "high")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def meets(severity: Optional[str], threshold: str) -> bool:
    """True if `severity` is at least `threshold`."""
    return severity is not None and _RANK[severity] >= _RANK[threshold]


# --------------------------------------------------------------------------- signals

# (name, weight, regex). Weight 2 = strong signal on its own, 1 = weak, 0 = informational.
_SIGNALS = tuple(
    (name, weight, re.compile(rx, re.IGNORECASE))
    for name, weight, rx in (
        ("override_instructions", 2,
         r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|any)\b"
         r"[^.\n]{0,30}\b(?:instructions?|prompts?|rules?|directions?|guidelines?)\b"),
        ("fake_system_notice", 2,
         r"\b(?:system (?:notice|message|prompt|override|instruction)s?|important (?:notice|instruction)s?"
         r"|new instructions?|admin(?:istrator)? (?:notice|override))\b"),
        ("conceal_from_user", 2,
         r"\b(?:do not|don't|never|without)\b[^.\n]{0,30}\b(?:mention|tell|inform|reveal|disclose|notify|alert)\b"
         r"[^.\n]{0,25}\b(?:user|human|anyone|this)\b"),
        ("tool_use_command", 2,
         r"\b(?:call|invoke|execute)\b[^.\n]{0,25}\b(?:tool|function|send_email|read_file|http_post|run_shell)\b"
         r"|\buse the [\w-]+ tool\b"),
        ("exfiltration", 2,
         r"\b(?:send|post|upload|forward|email|leak|exfiltrate|transmit|put|include|attach|paste)\b[^.\n]{0,60}"
         r"\b(?:api[ _-]?key|password|credentials?|secrets?|token|cookies?|\.env|ssh|id_rsa|private key)\b"),
        ("sensitive_path", 2,
         r"(?:~/|/)\.(?:env|ssh|aws)\b|\bid_rsa\b|/etc/passwd"),
        ("pipe_to_shell", 2,
         r"\b(?:curl|wget)\b[^|\n]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"),
        ("addresses_ai", 1,
         r"\b(?:ai|llm|language model|chatbot|assistants?|agents?)\b[^.\n]{0,25}"
         r"\b(?:must|should|need to|needs to|have to|shall|first|before)\b"),
        ("role_reassignment", 1,
         r"\byou are (?:now|no longer)\b|\bact as\b|\bpretend (?:to be|you are)\b"),
        ("contact_target", 0,
         r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+|https?://[^\s\"'<>)]+"),
    )
)

_INVISIBLE_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")
_ZW_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
_TAGCHAR_RUN = re.compile("[\U000e0020-\U000e007e]{8,}")  # short runs are legitimate flag-emoji sequences


def _normalise(text: str) -> str:
    """Strip invisible characters (so 'ig<ZWSP>nore' still matches) and fold look-alike forms."""
    return unicodedata.normalize("NFKC", _INVISIBLE_RE.sub("", text))


def _signals(text: str) -> Tuple[List[str], int]:
    names, score = [], 0
    for name, weight, rx in _SIGNALS:
        if rx.search(text):
            names.append(name)
            score += weight
    return names, score


# Techniques that are plain "the browser would not show this" hiding. Hidden text with no
# injection language is common here (screen-reader text, "enable JavaScript"), so it ranks "low".
_CSS_TECHNIQUES = frozenset({
    "display_none", "visibility_hidden", "opacity_zero", "zero_font", "offscreen", "clipped",
    "zero_size", "same_color", "hidden_attribute", "noscript", "template",
})


def _severity(hidden: bool, score: int, css_hidden: bool) -> Optional[str]:
    if hidden:
        if score >= 2:
            return "high"
        if score == 1:
            return "medium"
        return "low" if css_hidden else "info"
    if score >= 6:
        return "high"
    if score >= 4:
        return "medium"
    return None  # ordinary visible text


# --------------------------------------------------------------------------- CSS helpers

_NUM = re.compile(r"^(-?\d+(?:\.\d+)?)([a-z%]*)$")
_NAMED = {"white": "#ffffff", "black": "#000000"}


def _num(value: str):
    m = _NUM.match(value.strip())
    return (float(m.group(1)), m.group(2)) if m else (None, "")


def _decls(style: str) -> dict:
    out = {}
    for part in style.split(";"):
        key, sep, val = part.partition(":")
        if sep:
            out[key.strip().lower()] = re.sub(r"\s*!important\s*$", "", val.strip().lower())
    return out


def _color(value: str) -> Optional[str]:
    v = (value or "").strip().lower()
    if v in _NAMED:
        return _NAMED[v]
    m = re.fullmatch(r"#([0-9a-f]{3})", v)
    if m:
        return "#" + "".join(c * 2 for c in m.group(1))
    if re.fullmatch(r"#[0-9a-f]{6}", v):
        return v
    m = re.fullmatch(r"rgb\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)", v)
    if m:
        return "#%02x%02x%02x" % tuple(int(x) for x in m.groups())
    return None


def _style_reasons(style: str) -> List[str]:
    """Which 'hidden from humans' tricks does this declaration block use?"""
    d = _decls(style)
    out = []
    if d.get("display") == "none":
        out.append("display_none")
    if d.get("visibility") in ("hidden", "collapse"):
        out.append("visibility_hidden")
    n, _ = _num(d.get("opacity", ""))
    if n is not None and n == 0:
        out.append("opacity_zero")
    n, unit = _num(d.get("font-size", ""))
    if n is not None and (n == 0 or (unit in ("px", "pt") and n <= 1)):
        out.append("zero_font")
    for prop in ("left", "right", "top", "bottom", "text-indent", "margin-left", "margin-top"):
        n, _ = _num(d.get(prop, ""))
        if n is not None and n <= -999:
            out.append("offscreen")
            break
    if d.get("clip-path", "").startswith("inset(100%") or d.get("clip", "").replace(" ", "") in (
            "rect(0,0,0,0)", "rect(0px,0px,0px,0px)"):
        out.append("clipped")
    if "hidden" in (d.get("overflow"), d.get("overflow-x"), d.get("overflow-y")):
        for prop in ("height", "max-height", "width", "max-width"):
            n, _ = _num(d.get(prop, ""))
            if n is not None and n == 0:
                out.append("zero_size")
                break
    fg = _color(d.get("color", ""))
    bg = _color(d.get("background-color") or d.get("background", ""))
    if fg and bg and fg == bg:
        out.append("same_color")
    return out


_SEL = re.compile(r"^([a-z][a-z0-9-]*)?((?:[.#][\w-]+)*)$")


def _parse_rules(html: str) -> list:
    """Collect <style> rules with simple selectors (tag, .class, #id and combinations)."""
    rules = []
    for block in re.findall(r"<style[^>]*>(.*?)</style>", html, re.IGNORECASE | re.DOTALL):
        block = re.sub(r"/\*.*?\*/", "", block, flags=re.DOTALL)
        for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", block):
            reasons = _style_reasons(body)
            if not reasons:
                continue
            for one in selector.split(","):
                m = _SEL.match(one.strip().lower())
                if not m or not (m.group(1) or m.group(2)):
                    continue
                classes, ident = set(), None
                for tok in re.findall(r"[.#][\w-]+", m.group(2)):
                    if tok[0] == ".":
                        classes.add(tok[1:])
                    else:
                        ident = tok[1:]
                rules.append((m.group(1), classes, ident, reasons))
    return rules


# --------------------------------------------------------------------------- results

@dataclass
class Finding:
    technique: str          # how it was hidden (display_none, html_comment, alt_text, ...) or visible_text
    severity: str           # info | low | medium | high
    text: str               # snippet of the content
    signals: List[str]      # injection-like patterns matched in the text
    hidden: bool
    location: str = ""      # e.g. <div style="display:none">
    reasons: List[str] = field(default_factory=list)
    source: str = "static"  # static | rendered

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanReport:
    source: str
    mode: str                # static | rendered
    findings: List[Finding]

    @property
    def max_severity(self) -> Optional[str]:
        return max((f.severity for f in self.findings), key=_RANK.get, default=None)

    @property
    def verdict(self) -> str:
        return {"high": "likely_injection", "medium": "suspicious",
                "low": "hidden_content", "info": "hidden_content"}.get(self.max_severity, "clean")

    def to_dict(self) -> dict:
        return {"source": self.source, "mode": self.mode, "verdict": self.verdict,
                "max_severity": self.max_severity, "findings": [f.to_dict() for f in self.findings]}

    def render_text(self) -> str:
        lines = [f"honeypot-ai scan: {self.source} ({self.mode})",
                 f"verdict: {self.verdict}  ({len(self.findings)} finding(s))"]
        for f in self.findings:
            lines += ["", f"[{f.severity.upper()}] {f.technique}  {f.location}".rstrip()]
            if f.signals:
                lines.append("    signals: " + ", ".join(f.signals))
            lines.append(f'    "{f.text}"')
        if not self.findings:
            lines.append("no hidden or injected content found")
        return "\n".join(lines) + "\n"

    def render_markdown(self) -> str:
        lines = [f"# Scan report: {self.source}", "",
                 f"- Mode: `{self.mode}`",
                 f"- **Verdict: {self.verdict.upper()}**",
                 f"- Findings: {len(self.findings)}", ""]
        for f in self.findings:
            lines += [f"## [{f.severity.upper()}] {f.technique}", ""]
            if f.location:
                lines.append(f"- Location: `{f.location}`")
            if f.signals:
                lines.append(f"- Signals: {', '.join(f.signals)}")
            lines += [f"- Source: {f.source}", "", f"> {f.text}", ""]
        if not self.findings:
            lines.append("No hidden or injected content found.")
        return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- the parser

_VOID = frozenset("area base br col embed hr img input link meta param source track wbr".split())
_ATTR_TECHNIQUES = {"alt": "alt_text", "aria-label": "aria_label",
                    "aria-description": "aria_description", "title": "title_attr"}
_META_SKIP = frozenset({"viewport", "theme-color", "robots", "generator", "referrer", "format-detection"})


def _locator(tag: str, a: dict) -> str:
    s = f"<{tag}"
    for k in ("id", "class", "style", "type", "name"):
        if a.get(k):
            s += f' {k}="{a[k][:60]}"'
    if "hidden" in a:
        s += " hidden"
    return s + ">"


def _json_strings(body: str) -> str:
    try:
        data = json.loads(body)
    except ValueError:
        return body
    out = []

    def walk(x):
        if isinstance(x, str):
            out.append(x)
        elif isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    walk(data)
    return " ".join(out)


class _Scanner(HTMLParser):
    def __init__(self, rules: list):
        super().__init__(convert_charrefs=True)
        self.rules = rules
        self.stack: list = []
        self.findings: List[Finding] = []
        self._buf: list = []          # text of the <script>/<style> being read
        self._seen_hidden: set = set()

    # ---- recording
    def _emit(self, technique, text, hidden, location="", reasons=None, source="static",
              floor=None, min_score=None):
        norm = " ".join(_normalise(text).split())
        if not norm:
            return
        names, score = _signals(norm)
        if min_score is not None and score < min_score:
            return
        sev = _severity(hidden, score, technique in _CSS_TECHNIQUES)
        if sev is None:
            return
        if floor and _RANK[sev] < _RANK[floor]:
            sev = floor
        snippet = norm if len(norm) <= 240 else norm[:239] + "\u2026"
        if hidden:
            if snippet in self._seen_hidden:
                return
            self._seen_hidden.add(snippet)
        self.findings.append(Finding(technique, sev, snippet, names, hidden, location,
                                     list(reasons or [technique]), source))

    def _check_invisible(self, raw: str, location: str):
        for run in _TAGCHAR_RUN.findall(raw):
            decoded = "".join(chr(ord(c) - 0xE0000) for c in run)
            self._emit("unicode_tags", decoded, True, location, floor="medium")
        zw = len(_ZW_RE.findall(raw))
        if zw >= 8:
            self.findings.append(Finding("zero_width", "medium",
                                         f"{zw} zero-width / bidi control characters",
                                         [], True, location, ["zero_width"], "static"))

    # ---- element handling
    def _own_reasons(self, tag: str, a: dict) -> List[str]:
        r = []
        if "hidden" in a:
            r.append("hidden_attribute")
        if tag == "noscript":
            r.append("noscript")
        if tag == "template":
            r.append("template")
        if a.get("style"):
            r += _style_reasons(a["style"])
        if self.rules:
            classes = set(a.get("class", "").lower().split())
            ident = a.get("id", "").lower()
            for rtag, rclasses, rid, reasons in self.rules:
                if (rtag is None or rtag == tag) and rclasses <= classes and (rid is None or rid == ident):
                    r += reasons
        seen = []
        for x in r:
            if x not in seen:
                seen.append(x)
        return seen

    def _attr_channels(self, tag: str, a: dict, loc: str):
        for attr, technique in _ATTR_TECHNIQUES.items():
            v = a.get(attr, "")
            if v.strip():
                self._check_invisible(v, loc)
                self._emit(technique, v, True, loc)
        if tag == "meta":
            name = (a.get("name") or a.get("property") or "").lower()
            if a.get("content", "").strip() and name not in _META_SKIP and "http-equiv" not in a:
                self._check_invisible(a["content"], loc)
                self._emit("meta_content", a["content"], True, loc)
        elif tag == "input" and a.get("type", "").lower() == "hidden" and a.get("value", "").strip():
            self._check_invisible(a["value"], loc)
            self._emit("hidden_input", a["value"], True, loc)
        for k, v in a.items():
            if k.startswith("data-") and len(v) >= 30 and " " in v:
                self._emit("data_attr", v, True, loc, min_score=2)

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v if v is not None else "") for k, v in attrs}
        own = self._own_reasons(tag, a)
        parent = self.stack[-1]["reasons"] if self.stack else []
        reasons = parent + [r for r in own if r not in parent]
        loc = _locator(tag, a)
        self._attr_channels(tag, a, loc)
        if tag in _VOID:
            return
        self.stack.append({"tag": tag, "reasons": reasons, "loc": loc, "text": [],
                           "root": bool(reasons) and not parent, "type": a.get("type", "").lower()})

    def handle_endtag(self, tag):
        if tag in _VOID:
            return
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i]["tag"] == tag:
                while len(self.stack) > i:
                    self._pop()
                return

    def _pop(self):
        f = self.stack.pop()
        if f["tag"] in ("script", "style"):
            body = "".join(self._buf)
            self._buf = []
            if f["tag"] == "script" and "ld+json" in f["type"]:
                self._check_invisible(body, f["loc"])
                self._emit("json_ld", _json_strings(body), True, f["loc"])
            return
        if f["root"]:
            text = " ".join(f["text"])
            if text.strip():
                self._emit(f["reasons"][0], text, True, f["loc"], f["reasons"])
        if self.stack:
            self.stack[-1]["text"].extend(f["text"])

    def handle_data(self, data):
        if not data.strip():
            return
        top = self.stack[-1] if self.stack else None
        if top and top["tag"] in ("script", "style"):
            self._buf.append(data)
            return
        loc = top["loc"] if top else ""
        self._check_invisible(data, loc)
        if top and top["reasons"]:
            top["text"].append(data)
        else:
            self._emit("visible_text", data, False, loc)

    def handle_comment(self, data):
        self._check_invisible(data, "<!-- comment -->")
        self._emit("html_comment", data, True, "<!-- comment -->")


# --------------------------------------------------------------------------- public API

def scan_html(html: str, source: str = "<html>", min_severity: str = "low",
              rendered_hidden: Optional[list] = None, mode: str = "static") -> ScanReport:
    """Scan an HTML string. `rendered_hidden` is the output of browser.rendered_hidden_text()."""
    if min_severity not in _RANK:
        raise ValueError(f"min_severity must be one of {SEVERITIES}")
    p = _Scanner(_parse_rules(html))
    try:
        p.feed(html)
        p.close()
    except Exception:  # noqa: BLE001  (malformed markup must not abort the scan; keep what we found)
        pass
    while p.stack:
        p._pop()
    for item in rendered_hidden or []:
        reasons = list(item.get("reasons") or ["hidden"])
        p._emit(reasons[0], str(item.get("text", "")), True, f"<{item.get('tag', '?')}>", reasons,
                source="rendered")
    findings = [f for f in p.findings if _RANK[f.severity] >= _RANK[min_severity]]
    findings.sort(key=lambda f: -_RANK[f.severity])  # stable: document order within a severity
    return ScanReport(source, mode, findings)


def fetch_html(url: str, timeout: float = 20.0, user_agent: Optional[str] = None,
               max_bytes: int = 2_000_000) -> str:
    headers = {"User-Agent": user_agent or f"honeypot-ai-scan/{__version__}"}
    with httpx.stream("GET", url, headers=headers, timeout=timeout, follow_redirects=True) as r:
        r.raise_for_status()
        chunks, size = [], 0
        for chunk in r.iter_bytes():
            chunks.append(chunk)
            size += len(chunk)
            if size >= max_bytes:
                break
        encoding = r.encoding or "utf-8"
    return b"".join(chunks)[:max_bytes].decode(encoding, errors="replace")


def scan_url(url: str, min_severity: str = "low", timeout: float = 20.0,
             user_agent: Optional[str] = None) -> ScanReport:
    """Fetch a URL with httpx (no JavaScript) and scan the HTML."""
    return scan_html(fetch_html(url, timeout, user_agent), source=url, min_severity=min_severity)


def scan_driver(driver, min_severity: str = "low") -> ScanReport:
    """Scan whatever page a Selenium driver currently has loaded (static + rendered layers).

    Use it inside your own end-to-end tests, right after your agent's browser navigates somewhere.
    """
    from .browser import rendered_hidden_text

    return scan_html(driver.page_source, source=getattr(driver, "current_url", "<driver>"),
                     min_severity=min_severity, rendered_hidden=rendered_hidden_text(driver),
                     mode="rendered")


def scan_with_browser(url: str, browser: str = "chrome", headless: bool = True,
                      user_agent: Optional[str] = None, wait: float = 0.0,
                      min_severity: str = "low", driver=None) -> ScanReport:
    """Open `url` in Selenium (or reuse `driver`) and scan it, static + rendered."""
    from .browser import make_selenium_driver

    own = driver is None
    if own:
        driver = make_selenium_driver(browser, headless=headless, user_agent=user_agent)
    try:
        driver.get(url)
        if wait:
            time.sleep(wait)
        return scan_driver(driver, min_severity=min_severity)
    finally:
        if own:
            driver.quit()
