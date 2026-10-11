import os
import subprocess

import pytest

from tcv.network import DEFAULT_PROXY, ProxyConfigError, normalize_proxy, session_for


def run_tool(*args):
    return subprocess.run(
        ["python", *args],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": "."},
    )


def test_default_session_goes_through_tor_with_remote_dns():
    session = session_for(None, direct=False)
    assert session.proxies == {"http": DEFAULT_PROXY, "https": DEFAULT_PROXY}
    assert DEFAULT_PROXY.startswith("socks5h://")


def test_proxied_session_ignores_proxy_settings_from_the_environment():
    assert session_for(None, direct=False).trust_env is False


def test_host_and_port_mean_tor_style_socks_with_remote_dns():
    assert normalize_proxy("127.0.0.1:9150") == "socks5h://127.0.0.1:9150"


@pytest.mark.parametrize("proxy,suggested", [("socks5://localhost:9050", "socks5h://"), ("socks4://localhost:9050", "socks4a://")])
def test_socks_schemes_that_resolve_locally_are_refused(proxy, suggested):
    with pytest.raises(ProxyConfigError, match=suggested):
        normalize_proxy(proxy)


@pytest.mark.parametrize("proxy", ["socks5h://localhost:9050", "socks4a://localhost:9050", "http://127.0.0.1:8118"])
def test_proxies_that_resolve_remotely_are_kept(proxy):
    assert normalize_proxy(proxy) == proxy


def test_an_empty_proxy_is_an_error_not_a_direct_connection():
    with pytest.raises(ProxyConfigError, match="--direct"):
        session_for("", direct=False)


def test_direct_connections_need_the_explicit_flag():
    session = session_for(None, direct=True)
    assert session.proxies == {}


def test_proxy_and_direct_exclude_each_other():
    with pytest.raises(ProxyConfigError):
        session_for("socks5h://localhost:9050", direct=True)


def test_shadow_fetch_refuses_to_run_without_a_proxy(tmp_path):
    candidates = tmp_path / "candidates.json"
    candidates.write_text('["http://example.onion/a.txt"]')
    result = run_tool(
        "tools/shadow_fetch.py",
        "--input", str(candidates),
        "--out-dir", str(tmp_path / "out"),
        "--allowed-host", "example.onion",
        "--proxy", "",
    )
    assert result.returncode == 2
    assert "--direct" in result.stderr
    assert not (tmp_path / "out" / "metadata.jsonl").exists()


def test_abyssal_mapper_refuses_a_live_seed_with_a_leaking_proxy(tmp_path):
    result = run_tool(
        "tools/abyssal_mapper.py",
        "--url", "http://example.onion/",
        "--proxy", "socks5://localhost:9050",
        "--output", str(tmp_path / "graph.json"),
        "--graphml", str(tmp_path / "graph.graphml"),
    )
    assert result.returncode == 2
    assert "socks5h://" in result.stderr
    assert not (tmp_path / "graph.json").exists()


def test_abyssal_mapper_needs_no_proxy_for_local_inputs(tmp_path):
    result = run_tool(
        "tools/abyssal_mapper.py",
        "--html", "tests/fixtures/sample.html",
        "--proxy", "",
        "--output", str(tmp_path / "graph.json"),
        "--graphml", str(tmp_path / "graph.graphml"),
    )
    assert result.returncode == 0, result.stderr
