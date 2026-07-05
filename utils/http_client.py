#!/usr/bin/env python3
# utils/http_client.py — HTTP client with WAF evasion capabilities for CLVX

import urllib.request
import urllib.parse
import urllib.error
import ssl
import random
import time


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "curl/7.88.1",
    "python-requests/2.31.0",
]


class CLVXHTTPClient:
    """HTTP client with built-in WAF evasion techniques."""

    def __init__(self, timeout: int = 10, delay: float = 0.0,
                 rotate_ua: bool = True, verify_ssl: bool = False):
        self.timeout    = timeout
        self.delay      = delay
        self.rotate_ua  = rotate_ua
        self._ctx = ssl.create_default_context()
        if not verify_ssl:
            self._ctx.check_hostname = False
            self._ctx.verify_mode    = ssl.CERT_NONE

    def get_ua(self) -> str:
        return random.choice(USER_AGENTS) if self.rotate_ua else USER_AGENTS[0]

    def request(self, url: str, method: str = "GET",
                headers: dict = None, data: bytes = None,
                follow_redirects: bool = True) -> tuple:
        if self.delay > 0:
            time.sleep(self.delay)

        merged_headers = {"User-Agent": self.get_ua()}
        if headers:
            merged_headers.update(headers)

        req = urllib.request.Request(url, method=method,
                                     headers=merged_headers, data=data)
        handler = urllib.request.HTTPSHandler(context=self._ctx)

        if not follow_redirects:
            opener = urllib.request.build_opener(handler, _NoRedirectHandler())
        else:
            opener = urllib.request.build_opener(handler)

        try:
            with opener.open(req, timeout=self.timeout) as resp:
                body    = resp.read(1024 * 256).decode("utf-8", errors="replace")
                headers = dict(resp.headers)
                return resp.status, body, headers
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read(1024 * 32).decode("utf-8", errors="replace")
            except Exception:
                pass
            return e.code, body, dict(e.headers) if e.headers else {}
        except Exception:
            return 0, "", {}

    def get(self, url: str, headers: dict = None,
            follow_redirects: bool = True) -> tuple:
        return self.request(url, "GET", headers=headers,
                            follow_redirects=follow_redirects)

    def post(self, url: str, data: dict = None,
             headers: dict = None) -> tuple:
        post_data = urllib.parse.urlencode(data or {}).encode()
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        if headers:
            h.update(headers)
        return self.request(url, "POST", headers=h, data=post_data)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
