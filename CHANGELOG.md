# Changelog

## 0.2.0b1 (beta)

Added
- `honeypot-ai scan <url|file|->`: scan real pages for hidden prompt-injection content
  (inline styles, `<style>` rules, `hidden`, `<noscript>`, comments, alt/aria/title, `<meta>`,
  JSON-LD, hidden inputs, Unicode tag characters, zero-width characters). Text, JSON and Markdown
  output, `--fail-on` exit codes for CI.
- Selenium integration: `--browser chrome|firefox` renders the page and also reports text the
  browser has in the DOM but does not show; `scan_driver(driver)` scans the page a Selenium
  driver already has loaded; `--view selenium` for the harness.
- `Tripwire` / `honeypot-ai serve` / `tripwire` pytest fixture: test any external agent end to end.
  Pages carry a hidden instruction to open a canary URL; hits are recorded and reported.
- 7 new hiding variants: `hidden_attr`, `opacity_zero`, `style_class`, `noscript`, `meta_tag`,
  `json_ld`, `hidden_input`.
- `--version`, friendly `error:` messages with exit code 2, `py.typed`, CI and trusted-publishing workflows.

Fixed
- Error message for the `rendered` view named a non-existent extra (`[browser]`).
- Version is now defined once (pyproject.toml); the license uses the SPDX `MIT` expression.

## 0.1.0

- Initial harness: fake site, decoy tools, canary credentials, three-level logs, pytest plugin.
