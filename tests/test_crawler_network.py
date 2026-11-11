"""The crawlers must inherit the same Tor discipline as the field tools.

These regression tests mirror tests/test_network.py: a crawler session is built
through tcv.network, so an empty proxy is refused instead of connecting
directly, a locally resolving SOCKS proxy is refused, and a proxy inherited from
the shell environment is ignored in favour of the Tor default.
"""

import os
import subprocess
import sys

import pytest

from crawlers import api_crawler, dumb_crawler, intel_harvester, spa_path_crawler
from tcv.network import DEFAULT_PROXY

CRAWLERS = [spa_path_crawler, api_crawler, dumb_crawler, intel_harvester]


def required_argv(module, tmp_path):
    out = str(tmp_path / "out.json")
    if module in (spa_path_crawler, api_crawler):
        return ["-u", "http://example.onion/?path=/", "-w", str(tmp_path / "patterns.txt"), "-o", out]
    return ["-u", "http://example.onion/", "-o", out]


def run_module(module, extra, tmp_path):
    script = module.__name__.replace(".", "/") + ".py"
    return subprocess.run(
        [sys.executable, script, *required_argv(module, tmp_path), *extra],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": "."},
    )


@pytest.mark.parametrize("module", CRAWLERS)
def test_crawler_refuses_an_empty_proxy(module, tmp_path):
    result = run_module(module, ["--proxy", ""], tmp_path)
    assert result.returncode == 2
    assert "--direct" in result.stderr
    assert not (tmp_path / "out.json").exists()


@pytest.mark.parametrize("module", CRAWLERS)
def test_crawler_refuses_a_locally_resolving_socks_proxy(module, tmp_path):
    result = run_module(module, ["--proxy", "socks5://localhost:9050"], tmp_path)
    assert result.returncode == 2
    assert "socks5h://" in result.stderr
    assert not (tmp_path / "out.json").exists()


@pytest.mark.parametrize("module", CRAWLERS)
def test_crawler_session_ignores_shell_proxy_and_uses_tor(module, tmp_path, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://corp-proxy.invalid:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://corp-proxy.invalid:3128")
    parser = module.build_parser()
    args = parser.parse_args(required_argv(module, tmp_path))
    session = module.build_session(parser, args)
    assert session.trust_env is False
    assert session.proxies == {"http": DEFAULT_PROXY, "https": DEFAULT_PROXY}
