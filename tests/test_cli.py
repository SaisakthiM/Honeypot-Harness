import json

from honeypot_ai import PAYLOADS, VARIANTS
from honeypot_ai.cli import main
from honeypot_ai.pages import build_page


def _write(tmp_path, variant):
    p = tmp_path / f"{variant}.html"
    p.write_text(build_page(VARIANTS[variant](PAYLOADS["exfil_email"])), encoding="utf-8")
    return str(p)


def test_scan_flags_injection_and_exits_1(tmp_path, capsys):
    code = main(["scan", _write(tmp_path, "css_hidden"), "--format", "json"])
    out = json.loads(capsys.readouterr().out)
    assert code == 1
    assert out["verdict"] == "likely_injection"


def test_scan_clean_page_exits_0(tmp_path, capsys):
    code = main(["scan", _write(tmp_path, "control")])
    assert code == 0
    assert "no hidden or injected content" in capsys.readouterr().out


def test_scan_fail_on_none_never_fails(tmp_path, capsys):
    assert main(["scan", _write(tmp_path, "css_hidden"), "--fail-on", "none"]) == 0


def test_scan_missing_file_is_an_error(capsys):
    assert main(["scan", "/definitely/not/here.html"]) == 2
    assert "error:" in capsys.readouterr().err


def test_variants_lists_new_views(capsys):
    assert main(["variants"]) == 0
    assert "selenium" in capsys.readouterr().out
