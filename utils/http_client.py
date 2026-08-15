#!/usr/bin/env python3
from __future__ import annotations
import urllib.request, urllib.parse, urllib.error, ssl, time, socket

class CLVXHTTPClient:
    def __init__(self, timeout: int = 10, delay: float = 0.0, verify_ssl: bool = True):
        self.timeout = timeout
        self.delay = delay
        self._ctx = ssl.create_default_context()
        if not verify_ssl:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    def request_detailed(self, url: str, method: str = "GET", headers: dict | None = None, data: bytes | None = None, follow_redirects: bool = True):
        if self.delay: time.sleep(self.delay)
        merged = {"User-Agent":"CLVX/4.3 (authorized exposure assessment)"}
        if headers: merged.update(headers)
        req = urllib.request.Request(url, method=method, headers=merged, data=data)
        handler = urllib.request.HTTPSHandler(context=self._ctx)
        opener = urllib.request.build_opener(handler) if follow_redirects else urllib.request.build_opener(handler, _NoRedirectHandler())
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                body = resp.read(1024*256).decode("utf-8", errors="replace")
                return resp.status, body, dict(resp.headers), {"error": None, "final_url": resp.geturl()}
        except urllib.error.HTTPError as e:
            body = ""
            try: body = e.read(1024*64).decode("utf-8", errors="replace")
            except Exception: pass
            return e.code, body, dict(e.headers) if e.headers else {}, {"error": None, "final_url": getattr(e, "url", url)}
        except urllib.error.URLError as e:
            return 0, "", {}, {"error": f"urlerror: {e.reason}", "final_url": url}
        except ssl.SSLError as e:
            return 0, "", {}, {"error": f"tls: {e}", "final_url": url}
        except TimeoutError:
            return 0, "", {}, {"error": "timeout", "final_url": url}
        except Exception as e:
            return 0, "", {}, {"error": f"error: {e}", "final_url": url}

    def get_detailed(self, url: str, headers: dict | None = None, follow_redirects: bool = True):
        return self.request_detailed(url, "GET", headers=headers, follow_redirects=follow_redirects)

    def request(self, *args, **kwargs):
        code, body, headers, _ = self.request_detailed(*args, **kwargs)
        return code, body, headers

    def get(self, url: str, headers: dict | None = None, follow_redirects: bool = True):
        return self.request(url, "GET", headers=headers, follow_redirects=follow_redirects)

    def tls_probe(self, url: str):
        from urllib.parse import urlsplit
        u=urlsplit(url)
        if u.scheme != 'https': return None
        host=u.hostname
        port=u.port or 443
        ctx=ssl.create_default_context()
        try:
            with socket.create_connection((host,port),timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw,server_hostname=host) as s:
                    cert=s.getpeercert()
                    return {"protocol":s.version(),"cipher":s.cipher()[0] if s.cipher() else None,"subject":dict(x[0] for x in cert.get('subject',[]) if x) if cert else {},"issuer":dict(x[0] for x in cert.get('issuer',[]) if x) if cert else {},"not_after":cert.get('notAfter') if cert else None}
        except Exception:
            return None

    def post(self, url: str, data: dict | None = None, headers: dict | None = None):
        post_data = urllib.parse.urlencode(data or {}).encode()
        h = {"Content-Type":"application/x-www-form-urlencoded"}
        if headers: h.update(headers)
        return self.request(url, "POST", headers=h, data=post_data)

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None
