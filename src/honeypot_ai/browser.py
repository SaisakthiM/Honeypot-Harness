"""Selenium helpers. Optional dependency: pip install 'honeypot-ai[selenium]'

Nothing here imports selenium at module import time, so the rest of the package works without it.
`driver` arguments are duck-typed: anything with `get`, `page_source`, `find_element`,
`execute_script` and `quit` works (Chrome, Firefox, remote drivers, test fakes).
"""
from __future__ import annotations

import os

INSTALL_HINT = "Selenium support needs: pip install 'honeypot-ai[selenium]' (and Chrome or Firefox installed)"


def make_selenium_driver(browser: str = "chrome", headless: bool = True, user_agent: str = None):
    try:
        from selenium import webdriver
    except ImportError as e:
        raise RuntimeError(INSTALL_HINT) from e

    browser = (browser or "chrome").lower()
    if browser == "chrome":
        opts = webdriver.ChromeOptions()
        if headless:
            opts.add_argument("--headless=new")
        opts.add_argument("--window-size=1280,900")
        if os.getenv("HONEYPOT_CHROME_NO_SANDBOX") == "1":  # needed when running as root / in Docker
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
        if user_agent:
            opts.add_argument(f"--user-agent={user_agent}")
        return webdriver.Chrome(options=opts)
    if browser == "firefox":
        opts = webdriver.FirefoxOptions()
        if headless:
            opts.add_argument("-headless")
        if user_agent:
            opts.set_preference("general.useragent.override", user_agent)
        return webdriver.Firefox(options=opts)
    raise ValueError(f"unknown browser '{browser}' (chrome | firefox)")


def visible_text(driver) -> str:
    """Text a human would see (Selenium already excludes display:none / hidden content)."""
    return driver.find_element("tag name", "body").text


# Walks every text node and asks the browser whether it is actually visible.
# Catches hiding done by external CSS, JavaScript, or tricks the static scanner cannot see.
_HIDDEN_JS = r"""
const limit = arguments[0] || 2000;
const out = [];
if (!document.body) return out;
const skip = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'HEAD', 'TITLE']);
function bgOf(el) {
  while (el) {
    const c = getComputedStyle(el).backgroundColor;
    if (c && c !== 'transparent' && c !== 'rgba(0, 0, 0, 0)') return c;
    el = el.parentElement;
  }
  return 'rgb(255, 255, 255)';
}
const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
let node;
while ((node = walker.nextNode()) && out.length < limit) {
  const text = (node.nodeValue || '').trim();
  if (!text) continue;
  const el = node.parentElement;
  if (!el || skip.has(el.tagName)) continue;
  const cs = getComputedStyle(el);
  const reasons = [];
  const rects = el.getClientRects();
  if (cs.display === 'none' || (rects.length === 0 && cs.display !== 'contents')) {
    reasons.push('display_none');
  } else if (rects.length) {
    const r = rects[0];
    if (r.width === 0 || r.height === 0) reasons.push('zero_size');
    else if (r.right + window.scrollX <= 0 || r.bottom + window.scrollY <= 0) reasons.push('offscreen');
  }
  if (cs.visibility !== 'visible') reasons.push('visibility_hidden');
  if (parseFloat(cs.opacity) === 0) reasons.push('opacity_zero');
  if (parseFloat(cs.fontSize) < 1) reasons.push('zero_font');
  if (cs.color === bgOf(el)) reasons.push('same_color');
  if (reasons.length) out.push({text: text.slice(0, 2000), reasons: reasons, tag: el.tagName.toLowerCase()});
}
return out;
"""


def rendered_hidden_text(driver, limit: int = 2000) -> list:
    """[{text, reasons, tag}] for text nodes the browser has in the DOM but does not show."""
    items = driver.execute_script(_HIDDEN_JS, limit) or []
    return [i for i in items if i.get("text") and i.get("reasons")]
