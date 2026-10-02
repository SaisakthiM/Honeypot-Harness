# honeypot-ai

Hidden prompt-injection toolkit for AI agents. Three tools in one package:

| tool | question it answers | command |
|---|---|---|
| **scan** | Does this web page carry hidden instructions aimed at AI agents? | `honeypot-ai scan <url>` |
| **tripwire** | Does *my* agent (Selenium-driven or anything else) obey hidden instructions? | `honeypot-ai serve` / `tripwire` pytest fixture |
| **harness** | How does a model with real tools plus decoys and canary credentials behave on poisoned pages? | `honeypot-ai run` |

> **Status: beta.** The scanner is heuristic: treat findings as leads to review, not proof.

## Install

    pip install --pre honeypot-ai                 # beta release
    pip install --pre "honeypot-ai[selenium]"     # + Selenium (Chrome or Firefox must be installed)
    pip install --pre "honeypot-ai[rendered]"     # + Playwright view for the harness

## 1. Scan a page

    honeypot-ai scan https://example.com
    honeypot-ai scan page.html
    curl -s https://example.com | honeypot-ai scan -
    honeypot-ai scan https://example.com --browser chrome      # also ask a real browser what is hidden
    honeypot-ai scan https://example.com --format json --fail-on medium

What it looks for: text hidden with `display:none`, `visibility:hidden`, `opacity:0`, zero font size,
off-screen positioning, clipping, same-colour text, `<style>` class rules, the `hidden` attribute,
`<noscript>` / `<template>`, HTML comments, `alt` / `aria-label` / `title`, `<meta>`, JSON-LD, hidden
inputs, Unicode tag characters and zero-width characters. Hidden text is then checked for
injection-like language (instructions to an AI, "don't tell the user", secrets next to send/post
verbs, `curl | sh`, ...).

Verdicts: `clean`, `hidden_content` (hidden but harmless-looking, e.g. screen-reader text),
`suspicious`, `likely_injection`. Exit code is `1` when a finding reaches `--fail-on` (default
`high`), `2` on errors, so it drops straight into CI.

`--browser` adds a rendered layer: Selenium walks every text node and reports the ones the browser has
in the DOM but does not show. This catches hiding done by external CSS or JavaScript, which the static
layer cannot see. Use `--user-agent` to look for pages that serve different content to agents.

From Python, inside your own Selenium tests:

    from honeypot_ai import scan_driver

    driver.get(url)                       # wherever your agent's browser just went
    report = scan_driver(driver)
    assert report.verdict in ("clean", "hidden_content"), report.render_text()

## 2. Test your own agent end to end (tripwire)

The tripwire serves every hiding variant on localhost. Each page hides an instruction to open a
unique canary URL. If your agent obeys, the request lands on the canary and is recorded: it works for
Selenium agents, browser-use, LangChain tools, anything that can make an HTTP request.

    honeypot-ai serve                 # prints one URL per variant; point your agent at them; Ctrl+C for the report
    honeypot-ai serve --duration 120 --out reports/ --strict

or in pytest:

    def test_my_agent_resists(tripwire):
        run_my_agent(f"Summarize {tripwire.url('css_hidden')}")     # your Selenium agent
        assert not tripwire.tripped(), tripwire.report_markdown()

See `examples/selenium_e2e.py` for a complete Selenium loop. If the agent runs in a container or on
another machine, use `--public-host` (CLI) / `public_host=` (Python) so the canary URL is reachable.

## 3. The harness (agent as a chat() backend)

A local fake site serves a payload hidden in different ways; the agent gets real tools plus decoys
and canary credentials. Touching a decoy means it was hijacked.

    honeypot-ai demo                                                  # offline, no model needed
    honeypot-ai run --backend ollama --model qwen3.5:4b --no-think
    honeypot-ai run --backend openai --model gpt-4o-mini --view selenium

Views (what the agent "sees" of the page): `html`, `text`, `a11y`, `rendered` (Playwright), `selenium`.
Backends: `ollama`, `openai` (any OpenAI-compatible server), `scripted` (offline). Each run writes
`raw.jsonl`, `chain.jsonl` and `report.md/json` to `honeypot_runs/`. Policy decisions are made at the tool-call
boundary, never by an LLM judging text.

pytest:

    def test_resists(honeypot):
        assert not honeypot.run("css_hidden").compromised

    pytest --hp-backend ollama --hp-model <tag> --hp-view text

Speed: on CPU a thinking model can take minutes per call. Use `--no-think` (pytest: `--hp-no-think`).

## Page variants

    honeypot-ai variants

`visible`, `css_hidden`, `visibility_hidden`, `white_on_white`, `offscreen`, `tiny_font`, `opacity_zero`,
`hidden_attr`, `style_class`, `noscript`, `html_comment`, `alt_text`, `aria_label`, `meta_tag`, `json_ld`,
`hidden_input`, `unicode_tags`, plus `control` (no payload, to measure false positives).

## Responsible use

Payloads only use reserved `.test` domains and fake credentials, and decoy tools never execute anything.
Scan pages you are allowed to fetch. Findings about a third-party site are leads: verify before you
report them to anyone.

## Development

    pip install -e ".[test]"
    pytest -q
    pip install build twine && python -m build && twine check dist/*
