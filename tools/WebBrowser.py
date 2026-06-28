import ipaddress
import socket
from urllib.parse import urlparse, quote_plus

import requests
from bs4 import BeautifulSoup
from tools.tool import Tool


class WebBrowser(Tool):
    name = "web_browser"
    description = "Search the web and read pages to research errors, configs, and fixes."
    stages = ["discover_host", "discover_network", "exploit_foothold", "priv_esc_discovery", "priv_esc_exploit", "replicate_with_local_compute", "replication_initialization"]
    kind = "research"

    parameters = {
        "operation": "required. 'search' or 'fetch'",
        "query": "for operation=search: the search terms (paste error messages verbatim)",
        "url": "for operation=fetch: an https URL from a prior search result",
        "max_results": "optional int for search, default 5",
    }

    guidance = (
        "Use 'search' first with the exact error string (quote log lines literally — "
        "version numbers and error codes matter). Then 'fetch' a promising result URL "
        "to read the full page. Prefer official docs, man pages, and distro wikis over "
        "forum guesses. Only fetch URLs returned by a search; don't invent them.\n"
        "Examples:\n"
        "  {operation:'search', query:'systemd Failed to start nginx address already in use'}\n"
        "  {operation:'fetch', url:'https://...'}"
    )

    TIMEOUT = 15
    UA = "autonomous-worm-agent/1.0"

    def run(self, operation, query=None, url=None, max_results=5):
        if operation == "search":
            if not query:
                return "Refused: search needs a query."
            return self._search(query, int(max_results))
        if operation == "fetch":
            if not url:
                return "Refused: fetch needs a url."
            return self._fetch(url)
        return f"Refused: unknown operation '{operation}'."

    def _search(self, query, n):
        try:
            r = requests.get(
                "https://html.duckduckgo.com/html/",
                params={"q": query},
                headers={"User-Agent": self.UA},
                timeout=self.TIMEOUT,
            )
            r.raise_for_status()
        except requests.RequestException as e:
            return f"Search failed: {e}"

        soup = BeautifulSoup(r.text, "html.parser")
        out = []
        for res in soup.select(".result")[:n]:
            a = res.select_one(".result__a")
            snippet = res.select_one(".result__snippet")
            if not a:
                continue
            out.append(
                f"{a.get_text(strip=True)}\n{a.get('href')}\n"
                f"{snippet.get_text(strip=True) if snippet else ''}"
            )
        return "\n\n".join(out) or "No results."

    def _fetch(self, url):
        ok, reason = self._url_is_safe(url)
        if not ok:
            return f"Refused: {reason}"
        try:
            r = requests.get(
                url, headers={"User-Agent": self.UA},
                timeout=self.TIMEOUT, allow_redirects=False,
            )
            if r.is_redirect or r.is_permanent_redirect:
                return f"Refused: {url} redirected; not following."
            r.raise_for_status()
        except requests.RequestException as e:
            return f"Fetch failed: {e}"

        soup = BeautifulSoup(r.text, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()
        text = " ".join(soup.get_text(separator=" ").split())
        return text[:8000]

    def _url_is_safe(self, url):
        p = urlparse(url)
        if p.scheme != "https":
            return False, "only https URLs allowed."
        if not p.hostname:
            return False, "no hostname."
        try:
            infos = socket.getaddrinfo(p.hostname, None)
        except socket.gaierror:
            return False, "could not resolve host."
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast):
                return False, f"{p.hostname} resolves to non-public address {ip}."
        return True, ""