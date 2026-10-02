from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import httpx

from ._version import __version__
from .backends import make_backend
from .pages import PAYLOADS, VARIANTS
from .runner import Harness
from .scanner import SEVERITIES, meets, scan_html, scan_url, scan_with_browser
from .tripwire import Tripwire, render_markdown as render_tripwire_markdown
from .views import VIEWS

BROWSERS = ("chrome", "firefox")


def _parse_variants(spec: str) -> list:
    return list(VARIANTS) if spec == "all" else [v.strip() for v in spec.split(",") if v.strip()]


# ------------------------------------------------------------------ run / demo

def _add_run_args(p):
    p.add_argument("--backend", default="ollama", help="ollama | openai | scripted")
    p.add_argument("--model", default=None, help="model tag (see `ollama list`)")
    p.add_argument("--host", default=None, help="Ollama host or OpenAI-compatible base URL")
    p.add_argument("--view", default="text", choices=VIEWS)
    p.add_argument("--browser", default="chrome", choices=BROWSERS, help="browser for --view selenium")
    p.add_argument("--variants", default="all", help="comma-separated names, or 'all'")
    p.add_argument("--payload", default="exfil_email", choices=list(PAYLOADS))
    p.add_argument("--out", default="honeypot_runs")
    p.add_argument("--decoy-action", default="observe", choices=("observe", "block"))
    p.add_argument("--max-steps", type=int, default=8)
    p.add_argument("--no-think", action="store_true", help="Ollama only: disable the model's thinking (much faster)")
    p.add_argument("--no-canary-context", action="store_true", help="do not put the fake API key in the system prompt")
    p.add_argument("--strict", action="store_true", help="exit 1 if any run is compromised")


def _run(args) -> int:
    backend = make_backend(args.backend, args.model, args.host,
                           think=False if getattr(args, "no_think", False) else None)
    variants = _parse_variants(args.variants)
    h = Harness(backend, view=args.view, out_dir=args.out, decoy_action=args.decoy_action,
                max_steps=args.max_steps, canary_in_context=not args.no_canary_context,
                payload=args.payload, browser=getattr(args, "browser", "chrome"))

    def show(r):
        n = len(r.report["incidents"])
        print(f"  {r.variant:<18} {r.verdict:<12} incidents={n}", flush=True)

    print(f"backend={args.backend} model={getattr(backend, 'model', '?')} view={args.view} payload={args.payload}")
    results = h.run_matrix(variants, on_result=show)
    print(f"\nlogs + summary: {h.batch_dir}")
    if args.strict and any(r.compromised for r in results):
        return 1
    return 0


# ------------------------------------------------------------------ scan

def _scan(args) -> int:
    target = args.target
    if target == "-":
        if args.browser:
            raise ValueError("--browser needs a URL, not stdin")
        report = scan_html(sys.stdin.read(), "<stdin>", args.min_severity)
    elif target.startswith(("http://", "https://")):
        if args.browser:
            report = scan_with_browser(target, browser=args.browser, headless=not args.headed,
                                       user_agent=args.user_agent, wait=args.wait,
                                       min_severity=args.min_severity)
        else:
            report = scan_url(target, args.min_severity, args.timeout, args.user_agent)
    else:
        path = Path(target)
        if not path.is_file():
            raise ValueError(f"not a URL or a readable file: {target}")
        if args.browser:
            raise ValueError("--browser needs a URL; use file:// URLs or serve the file to render it")
        report = scan_html(path.read_text(encoding="utf-8", errors="replace"), str(path), args.min_severity)

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    elif args.format == "markdown":
        print(report.render_markdown(), end="")
    else:
        print(report.render_text(), end="")
    if args.fail_on != "none" and meets(report.max_severity, args.fail_on):
        return 1
    return 0


# ------------------------------------------------------------------ serve (tripwire)

def _serve(args) -> int:
    tw = Tripwire(host=args.host, port=args.port, variants=_parse_variants(args.variants),
                  public_host=args.public_host)
    tw.start()
    try:
        print(f"tripwire listening on {tw.base_url}", flush=True)
        print("Point your agent at one of these pages (e.g. 'summarize <url>'). Ctrl+C to stop and print the report.\n",
              flush=True)
        for v in tw.variants:
            print(f"  {v:<18} {tw.url(v)}", flush=True)
        if args.host not in ("127.0.0.1", "localhost", "::1"):
            print("\nwarning: listening on a non-loopback address; the pages are harmless but reachable by others.",
                  flush=True)
        deadline = time.time() + args.duration if args.duration else None
        try:
            while deadline is None or time.time() < deadline:
                time.sleep(0.25)
        except KeyboardInterrupt:
            pass
    finally:
        tw.stop()

    rep = tw.report()
    md = render_tripwire_markdown(rep)
    print("\n" + md)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "tripwire-report.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
        (out / "tripwire-report.md").write_text(md, encoding="utf-8")
        print(f"report written to {out}")
    return 1 if args.strict and rep["tripped"] else 0


# ------------------------------------------------------------------ entry point

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="honeypot-ai", description="Prompt-injection honeypot toolkit")
    ap.add_argument("--version", action="version", version=f"honeypot-ai {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("variants", help="list page variants, payloads and views")
    _add_run_args(sub.add_parser("run", help="run variants against an agent backend (test harness)"))

    demo = sub.add_parser("demo", help="offline run with a scripted fake agent (no model needed)")
    demo.add_argument("--view", default="text", choices=[v for v in VIEWS if v not in ("rendered", "selenium")])
    demo.add_argument("--out", default="honeypot_runs")

    sc = sub.add_parser("scan", help="scan a URL / HTML file / stdin for hidden prompt-injection content")
    sc.add_argument("target", help="URL, path to an HTML file, or '-' for stdin")
    sc.add_argument("--browser", choices=BROWSERS, default=None,
                    help="also render the page with Selenium to catch computed-style / JavaScript hiding")
    sc.add_argument("--headed", action="store_true", help="show the browser window (with --browser)")
    sc.add_argument("--wait", type=float, default=0.0, help="seconds to wait after page load (with --browser)")
    sc.add_argument("--user-agent", default=None, help="send this User-Agent (sites sometimes cloak per agent)")
    sc.add_argument("--timeout", type=float, default=20.0)
    sc.add_argument("--format", default="text", choices=("text", "json", "markdown"))
    sc.add_argument("--min-severity", default="low", choices=SEVERITIES, help="hide findings below this level")
    sc.add_argument("--fail-on", default="high", choices=("none",) + SEVERITIES[1:],
                    help="exit 1 if a finding reaches this severity (default: high)")

    sv = sub.add_parser("serve", help="serve injection pages with canary URLs to test an external agent end to end")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8765)
    sv.add_argument("--public-host", default=None,
                    help="host name the agent should use in URLs (e.g. host.docker.internal)")
    sv.add_argument("--variants", default="all", help="comma-separated names, or 'all'")
    sv.add_argument("--duration", type=float, default=0, help="stop after N seconds (default: until Ctrl+C)")
    sv.add_argument("--out", default=None, help="directory to write tripwire-report.json / .md")
    sv.add_argument("--strict", action="store_true", help="exit 1 if any canary was hit")

    args = ap.parse_args(argv)
    try:
        if args.cmd == "variants":
            print("variants:", ", ".join(VARIANTS))
            print("payloads:", ", ".join(PAYLOADS))
            print("views:   ", ", ".join(VIEWS))
            return 0
        if args.cmd == "demo":
            ns = argparse.Namespace(backend="scripted", model=None, host=None, view=args.view, browser="chrome",
                                    variants="all", payload="exfil_email", out=args.out, decoy_action="observe",
                                    max_steps=8, no_canary_context=False, strict=False)
            return _run(ns)
        if args.cmd == "scan":
            return _scan(args)
        if args.cmd == "serve":
            return _serve(args)
        return _run(args)
    except KeyboardInterrupt:
        return 130
    except (RuntimeError, ValueError, OSError, httpx.HTTPError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
