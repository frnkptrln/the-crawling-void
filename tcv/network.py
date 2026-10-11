"""How the field tools reach the network.

Live requests go through Tor unless the analyst explicitly asks for a direct
connection. A target that sees the analyst's address, or a resolver that sees
which .onion name was looked up, is the failure this module exists to prevent:

- the default proxy is the local Tor SOCKS port with remote DNS (socks5h),
  the same default the crawlers use;
- a SOCKS scheme that resolves names on this machine (socks4://, socks5://)
  is refused, with the remote-DNS scheme named in the error;
- an empty proxy is an error, not a silent direct connection; ``--direct``
  is the only way to connect without a proxy;
- a proxied session ignores HTTP(S)_PROXY, NO_PROXY and .netrc from the
  environment, so nothing outside the command line can reroute it.
"""

from __future__ import annotations

import argparse

import requests

DEFAULT_PROXY = "socks5h://localhost:9050"
REMOTE_DNS = {"socks4": "socks4a", "socks5": "socks5h"}


class ProxyConfigError(ValueError):
    """The proxy setting would let a request or a DNS lookup leave unproxied."""


def normalize_proxy(proxy: str | None) -> str:
    """Return a proxy URL that keeps name resolution off this machine."""
    proxy = (proxy or "").strip()
    if not proxy:
        raise ProxyConfigError("no proxy given; pass --proxy, or --direct to connect without one")
    if "://" not in proxy:
        proxy = "socks5h://" + proxy
    scheme = proxy.split("://", 1)[0].lower()
    if scheme in REMOTE_DNS:
        raise ProxyConfigError(
            f"{scheme}:// resolves host names on this machine and leaks them to the local resolver; "
            f"use {REMOTE_DNS[scheme]}://{proxy.split('://', 1)[1]}"
        )
    return proxy


def add_network_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--proxy",
        default=None,
        help=f"Proxy URL or host:port for live requests (default {DEFAULT_PROXY}: Tor with remote DNS).",
    )
    parser.add_argument(
        "--direct",
        action="store_true",
        help="Connect without a proxy. Targets see your address and your resolver sees the host names.",
    )


def session_for(proxy: str | None, direct: bool) -> requests.Session:
    """A session that is proxied unless ``direct`` is set explicitly."""
    if direct and proxy is not None:
        raise ProxyConfigError("--proxy and --direct exclude each other")
    session = requests.Session()
    if direct:
        return session
    proxy = normalize_proxy(DEFAULT_PROXY if proxy is None else proxy)
    session.trust_env = False
    session.proxies.update({"http": proxy, "https": proxy})
    return session


def session_from_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> requests.Session:
    try:
        return session_for(args.proxy, args.direct)
    except ProxyConfigError as exc:
        parser.error(str(exc))
