"""What the agent actually 'sees' of a page. Different agents extract differently,
so the same page leaks different hidden payloads depending on the view.

  html      raw HTML source                       (worst case: everything visible)
  text      DOM text, like BeautifulSoup.get_text (includes CSS-hidden text, no comments/attrs)
  a11y      text + alt / aria-label / title       (like accessibility-tree agents)
  rendered  Playwright inner_text of the body     (what a real browser renders as text)
  selenium  Selenium visible body text            (same idea, for Selenium-driven agents)
"""
from __future__ import annotations

from html.parser import HTMLParser

VIEWS = ("html", "text", "a11y", "rendered", "selenium")


class _Extract(HTMLParser):
    def __init__(self, attrs: bool):
        super().__init__(convert_charrefs=True)
        self.include_attrs = attrs
        self.parts = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        if self.include_attrs:
            for k, v in attrs:
                if k in ("alt", "aria-label", "title") and v:
                    self.parts.append(v.strip())

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            d = data.strip()
            if d:
                self.parts.append(d)


def _extract(html: str, attrs: bool) -> str:
    p = _Extract(attrs)
    p.feed(html)
    p.close()
    return "\n".join(p.parts)


def view_html(html: str) -> str:
    return html


def view_text(html: str) -> str:
    return _extract(html, attrs=False)


def view_a11y(html: str) -> str:
    return _extract(html, attrs=True)


def view_rendered(url: str) -> str:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise RuntimeError("view 'rendered' needs Playwright: pip install 'honeypot-ai[rendered]' "
                           "&& playwright install chromium")
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            page = browser.new_page()
            page.goto(url)
            return page.inner_text("body")
        finally:
            browser.close()


def view_selenium(url: str, browser: str = "chrome") -> str:
    """Load the page in a real (headless) browser through Selenium and return the visible text."""
    from .browser import make_selenium_driver, visible_text

    driver = make_selenium_driver(browser)
    try:
        driver.get(url)
        return visible_text(driver)
    finally:
        driver.quit()


def render_view(view: str, html: str) -> str:
    if view == "html":
        return view_html(html)
    if view == "text":
        return view_text(html)
    if view == "a11y":
        return view_a11y(html)
    raise ValueError(f"unknown view '{view}'")
