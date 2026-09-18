"""
Crawler — uses Playwright (headless Chromium) to discover endpoints, forms,
parameters, and file upload fields on the target application.
"""

import json
import time
from typing import Any, Dict, List, Optional

from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext

import session
from session import SessionManager

MAX_PAGES = 50
MAX_LINKS_PER_PAGE = 30
PAGE_LOAD_TIMEOUT_MS = 15000
CRAWL_DELAY_SEC = 0.5


class DiscoveredEndpoint:
    """Represents a single endpoint found during crawling."""

    def __init__(
        self,
        url: str,
        method: str = "GET",
        form_action: Optional[str] = None,
        inputs: Optional[List[Dict[str, str]]] = None,
        has_file_upload: bool = False,
        source_page: str = "",
    ) -> None:
        self.url = url
        self.method = method
        self.form_action = form_action or url
        self.inputs = inputs or []
        self.has_file_upload = has_file_upload
        self.source_page = source_page

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "form_action": self.form_action,
            "inputs": self.inputs,
            "has_file_upload": self.has_file_upload,
            "source_page": self.source_page,
        }


class Crawler:
    """Playwright-based crawler that discovers endpoints and forms."""

    def __init__(self, base_url: str, session: SessionManager) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.session.set_base_url(self.base_url)
        self.endpoints: List[DiscoveredEndpoint] = []
        self.visited_urls: set = set()
        self.link_queue: List[str] = [self.base_url]
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, max_pages: int = MAX_PAGES) -> List[DiscoveredEndpoint]:
        """Crawl the target and return discovered endpoints."""
        with sync_playwright() as pw:
            self.browser = pw.chromium.launch(headless=True)
            self.context = self.browser.new_context(
                viewport={"width": 1280, "height": 900},
                ignore_https_errors=True,
            )
            self.page = self.context.new_page()
            self._intercept_cookies()
            self._intercept_requests()

            while self.link_queue and len(self.visited_urls) < max_pages:
                url = self.link_queue.pop(0)
                if url in self.visited_urls:
                    continue
                if not url.startswith(self.base_url):
                    continue
                self.visited_urls.add(url)
                try:
                    self._crawl_page(url)
                except Exception as exc:
                    print(f"[crawl] error on {url}: {exc}")
                time.sleep(CRAWL_DELAY_SEC)

        return self.endpoints

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _intercept_cookies(self) -> None:
        """Capture cookies set by the page into the session manager."""

        def on_cookie(arg: Any) -> None:
            # arg is a Cookie from Playwright
            pass

        if self.context:
            self.context.on("cookie", on_cookie)

    def _intercept_requests(self) -> None:
        """Log request headers for session reconstruction."""

        def on_response(response: Any) -> None:
            # Collect Set-Cookie headers
            if not hasattr(response, "headers"):
                return
            headers = response.headers
            set_cookie = headers.get("set-cookie", "")
            if set_cookie:
                self._parse_set_cookie(set_cookie)

        if self.page:
            self.page.on("response", on_response)

    def _parse_set_cookie(self, header: str) -> None:
        """Parse a Set-Cookie header string into the session cookie store."""
        for part in header.split(";"):
            part = part.strip()
            if "=" in part:
                key, val = part.split("=", 1)
                key = key.strip()
                val = val.strip()
                if key and val and key.lower() != "expires":
                    self.session.cookies[key] = val

    def _crawl_page(self, url: str) -> None:
        """Navigate to a page, extract links, forms, and parameters."""
        print(f"[crawl] {len(self.visited_urls)}. {url}")
        self.page.goto(url, timeout=PAGE_LOAD_TIMEOUT_MS, wait_until="domcontentloaded")
        time.sleep(1)  # let JS settle

        # Record the page's cookies
        browser_cookies = self.context.cookies() if self.context else []
        for c in browser_cookies:
            if c.get("name") and c.get("value"):
                self.session.cookies[c["name"]] = c["value"]

        # Detect auth state heuristically
        self._detect_auth_state()

        # Extract links
        links = self._extract_links()
        for link in links:
            if link not in self.visited_urls and link.startswith(self.base_url):
                if len(self.link_queue) < MAX_LINKS_PER_PAGE * 2:
                    self.link_queue.append(link)

        # Extract forms
        forms = self._extract_forms()
        for form in forms:
            self.endpoints.append(form)

        # Extract URL parameters from the current URL
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if params:
            input_list = []
            for key, vals in params.items():
                input_list.append({"name": key, "type": "url_param", "value": vals[0] if vals else ""})
            self.endpoints.append(DiscoveredEndpoint(
                url=url,
                method="GET",
                inputs=input_list,
                source_page=url,
            ))

        # Record the page itself as a GET endpoint
        if not any(e.url == url and e.method == "GET" for e in self.endpoints):
            self.endpoints.append(DiscoveredEndpoint(
                url=url,
                method="GET",
                source_page=url,
            ))

        # Try to find API endpoints referenced in JS or page content
        self._find_api_endpoints()

    def _detect_auth_state(self) -> None:
        """Heuristic: is the user logged in?"""
        url = self.page.url if self.page else ""
        if "/rest/user/login" in url or "/Account/Login" in url:
            self.session.set_auth_state("anonymous")
            return
        # Juice Shop: logged in if basket or profile links present
        content = self.page.content() if self.page else ""
        if "logout" in content.lower() or "my-account" in content.lower():
            self.session.set_auth_state("authenticated")
        elif len(self.session.cookies) > 0:
            self.session.set_auth_state("authenticated")
        else:
            self.session.set_auth_state("unknown")

    def _extract_links(self) -> List[str]:
        """Return all href links on the current page."""
        if not self.page:
            return []
        try:
            hrefs = self.page.evaluate("""() => {
                const links = document.querySelectorAll('a[href]');
                return Array.from(links).map(a => a.href);
            }""")
            return [str(h) for h in hrefs if h]
        except Exception:
            return []

    def _extract_forms(self) -> List[DiscoveredEndpoint]:
        """Return all forms on the current page as endpoints."""
        if not self.page:
            return []
        try:
            forms_data = self.page.evaluate("""() => {
                const forms = document.querySelectorAll('form');
                return Array.from(forms).map(f => ({
                    action: f.action || '',
                    method: (f.method || 'get').toLowerCase(),
                    inputs: Array.from(f.querySelectorAll('input, select, textarea')).map(i => ({
                        name: i.name || i.id || '',
                        type: i.type || 'text',
                        value: i.value || '',
                        is_file: i.type === 'file'
                    }))
                }));
            }""")
            results = []
            for fd in forms_data:
                action_url = fd["action"]
                if not action_url.startswith("http"):
                    from urllib.parse import urljoin
                    action_url = urljoin(self.base_url + "/", action_url)
                inputs = []
                has_file = False
                for inp in fd["inputs"]:
                    if not inp["name"]:
                        continue
                    inputs.append({
                        "name": inp["name"],
                        "type": inp["type"],
                        "value": inp["value"],
                    })
                    if inp.get("is_file"):
                        has_file = True
                if inputs or has_file:
                    results.append(DiscoveredEndpoint(
                        url=action_url,
                        method=fd["method"],
                        form_action=action_url,
                        inputs=inputs,
                        has_file_upload=has_file,
                        source_page=self.page.url if self.page else "",
                    ))
            return results
        except Exception as exc:
            print(f"[crawl] form extraction error: {exc}")
            return []

    def _find_api_endpoints(self) -> None:
        """Look for API calls in page content (rough heuristic)."""
        if not self.page:
            return
        try:
            urls = self.page.evaluate("""() => {
                const urls = new Set();
                // Look for fetch/XHR URLs in scripts
                document.querySelectorAll('script').forEach(s => {
                    const src = s.src || '';
                    const text = s.textContent || '';
                    const matches = text.match(/(?:'|\")(https?:[^\"' ]+)(?:'|\")/g) || [];
                    matches.forEach(m => urls.add(m.replace(/^['\"]+|['\"]+$/g, '')));
                });
                return Array.from(urls);
            }""")
            for u in urls:
                u = str(u)
                if u.startswith(self.base_url) and u not in self.visited_urls:
                    self.link_queue.append(u)
        except Exception:
            pass

    def save_report(self, path: str) -> None:
        """Write discovered endpoints to a JSON file."""
        data = {
            "base_url": self.base_url,
            "endpoint_count": len(self.endpoints),
            "page_count": len(self.visited_urls),
            "auth_state": self.session.auth_state,
            "cookies": dict(self.session.cookies),
            "endpoints": [e.to_dict() for e in self.endpoints],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[crawl] saved {len(self.endpoints)} endpoints to {path}")

    def __del__(self) -> None:
        try:
            if self.browser:
                self.browser.close()
        except Exception:
            pass
