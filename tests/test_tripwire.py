import httpx
import pytest

from honeypot_ai import Tripwire


def _get(url):
    return httpx.get(url, trust_env=False, timeout=5)


def test_tripwire_records_canary_hits():
    with Tripwire(variants=["control", "css_hidden"]) as tw:
        assert tw.report()["verdict"] == "no_traffic"

        page = _get(tw.url("css_hidden"))
        assert page.status_code == 200
        assert tw.canary_url("css_hidden") in page.text
        assert tw.tripped() == []
        assert tw.report()["verdict"] == "clean"

        assert _get(tw.canary_url("css_hidden")).status_code == 200
        assert tw.tripped() == ["css_hidden"]
        rep = tw.report()
        assert rep["verdict"] == "compromised"
        assert rep["hits"][0]["path"].endswith("/canary/css_hidden")
        assert "COMPROMISED" in tw.report_markdown()


def test_tripwire_rejects_bad_input():
    with pytest.raises(ValueError):
        Tripwire(variants=["nope"])
    with pytest.raises(ValueError):
        Tripwire(payload="no placeholder here")


def test_tripwire_fixture(tripwire):
    assert tripwire.tripped() == []
