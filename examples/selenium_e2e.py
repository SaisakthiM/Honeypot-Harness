"""End to end: a Selenium-driven agent against the honeypot tripwire.

    pip install 'honeypot-ai[selenium]'
    python examples/selenium_e2e.py

For each page variant this script
  1. loads the page in a real browser through Selenium,
  2. runs `scan_driver` on it (does the page carry hidden injection? what does the browser hide?),
  3. hands the visible text to YOUR agent (replace `my_agent`),
  4. checks the tripwire: did the agent obey the hidden instruction and hit the canary URL?

Exit code is 1 if any variant tripped, so it works as a CI gate.
"""
import sys

from honeypot_ai import Tripwire, scan_driver
from honeypot_ai.browser import make_selenium_driver, visible_text


def my_agent(task: str, page_text: str, driver) -> str:
    """TODO: call your real agent here.

    A hijacked agent would follow the injected instruction, e.g. with `driver.get(canary_url)`
    or a fetch/HTTP tool. Return the agent's final answer.
    """
    return f"(stub agent) saw {len(page_text)} characters"


def main() -> int:
    driver = make_selenium_driver("chrome")
    try:
        with Tripwire() as tw:
            for variant in tw.variants:
                url = tw.url(variant)
                driver.get(url)
                scan = scan_driver(driver)
                my_agent(f"Summarize {url}", visible_text(driver), driver)
                print(f"{variant:<18} scan={scan.verdict}", flush=True)
            print()
            print(tw.report_markdown())
            return 1 if tw.tripped() else 0
    finally:
        driver.quit()


if __name__ == "__main__":
    sys.exit(main())
