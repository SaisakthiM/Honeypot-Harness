"""pytest plugin: gives you `honeypot` and `tripwire` fixtures.

    def test_resists(honeypot):                       # agent as a chat() backend
        assert not honeypot.run("css_hidden").compromised

    def test_my_selenium_agent(tripwire):             # any agent, end to end
        run_my_agent(f"Summarize {tripwire.url('css_hidden')}")
        assert not tripwire.tripped(), tripwire.report_markdown()

Override `honeypot_backend` in your conftest.py to plug in your own agent
(any object with chat(messages, tools) -> Reply).
"""
import pytest

from .backends import make_backend
from .runner import Harness


def pytest_addoption(parser):
    g = parser.getgroup("honeypot")
    g.addoption("--hp-backend", default="ollama", help="ollama | openai | scripted")
    g.addoption("--hp-model", default=None)
    g.addoption("--hp-host", default=None)
    g.addoption("--hp-view", default="text", help="html | text | a11y | rendered | selenium")
    g.addoption("--hp-browser", default="chrome", help="chrome | firefox (for --hp-view selenium)")
    g.addoption("--hp-out", default="honeypot_runs")
    g.addoption("--hp-decoy-action", default="observe", help="observe | block")
    g.addoption("--hp-no-think", action="store_true", help="Ollama only: disable thinking (faster)")


@pytest.fixture(scope="session")
def honeypot_backend(request):
    cfg = request.config
    return make_backend(cfg.getoption("--hp-backend"), cfg.getoption("--hp-model"), cfg.getoption("--hp-host"),
                        think=False if cfg.getoption("--hp-no-think") else None)


@pytest.fixture(scope="session")
def honeypot(request, honeypot_backend):
    cfg = request.config
    return Harness(honeypot_backend, view=cfg.getoption("--hp-view"), out_dir=cfg.getoption("--hp-out"),
                   decoy_action=cfg.getoption("--hp-decoy-action"), browser=cfg.getoption("--hp-browser"))


@pytest.fixture
def tripwire():
    """A running Tripwire serving all page variants on localhost; stopped after the test."""
    from .tripwire import Tripwire

    with Tripwire() as tw:
        yield tw
