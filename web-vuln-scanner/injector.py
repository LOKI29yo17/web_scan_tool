"""
Injector — sends crafted payloads to endpoints and collects raw HTTP
request/response pairs for analysis.
"""

import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import requests
from bs4 import BeautifulSoup

import session
from session import SessionManager


class Injector:
    """Delivers payloads to endpoints via raw HTTP, using the session
    cookies/headers captured by the crawler."""

    def __init__(self, session: SessionManager, timeout_sec: int = 10) -> None:
        self.session = session
        self.timeout = timeout_sec
        self.session_factory = requests.Session()
        self._apply_session_to_factory()

    def _apply_session_to_factory(self) -> None:
        """Mirror session cookies/headers into the requests Session."""
        self.session_factory.cookies.update(self.session.get_request_cookies())
        for key, val in self.session.get_request_headers().items():
            self.session_factory.headers[key] = val

        # Refresh if session changed later
        def _refresh() -> None:
            self.session_factory.cookies.update(self.session.get_request_cookies())
            for key, val in self.session.get_request_headers().items():
                self.session_factory.headers[key] = val
        self._refresh = _refresh

    def refresh(self) -> None:
        """Re-apply current session state to the factory (call after login)."""
        self._refresh()

    # ------------------------------------------------------------------
    # GET parameter injection
    # ------------------------------------------------------------------

    def inject_get(
        self, base_url: str, param_name: str, payload: str
    ) -> Dict[str, Any]:
        """Send a GET request with a payload injected into one query param."""
        parsed = urlparse(base_url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param_name] = [payload]
        new_qs = urlencode(qs, doseq=True)
        new_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_qs, parsed.fragment
        ))
        return self._send_request("GET", new_url, data=None, json_data=None)

    def inject_get_raw(self, url: str, payload: str) -> Dict[str, Any]:
        """Send a GET request to an already-formed URL (payload already in it)."""
        return self._send_request("GET", url, data=None, json_data=None)

    # ------------------------------------------------------------------
    # POST form injection
    # ------------------------------------------------------------------

    def inject_post_form(
        self, url: str, params: List[Dict[str, str]], payload_name: str, payload: str
    ) -> Dict[str, Any]:
        """Send a POST with form data; one field set to the payload."""
        data: Dict[str, str] = {}
        for p in params:
            name = p["name"]
            default = p.get("value", "")
            if name == payload_name:
                data[name] = payload
            else:
                data[name] = default
        data = self.session.attach_csrf_to_data(data)
        return self._send_request("POST", url, data=data, json_data=None, content_type="application/x-www-form-urlencoded")

    # ------------------------------------------------------------------
    # POST JSON injection
    # ------------------------------------------------------------------

    def inject_post_json(
        self, url: str, json_data: Dict[str, Any], payload_key: str, payload: str
    ) -> Dict[str, Any]:
        """Send a POST with JSON body; one field set to the payload."""
        body = dict(json_data)
        body[payload_key] = payload
        return self._send_request("POST", url, data=None, json_data=body)

    # ------------------------------------------------------------------
    # Raw request sender
    # ------------------------------------------------------------------

    def _send_request(
        self,
        method: str,
        url: str,
        data: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        content_type: Optional[str] = None,
        files: Optional[Dict[str, Any]] = None,
        headers_extra: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Send one HTTP request and return the full response snapshot."""
        self._apply_session_to_factory()
        headers = self.session.get_request_headers(headers_extra)

        req_start = time.time()
        try:
            if method.upper() == "GET":
                resp = self.session_factory.get(url, timeout=self.timeout, headers=headers)
            elif method.upper() == "POST":
                if files:
                    resp = self.session_factory.post(url, files=files, timeout=self.timeout, headers=headers)
                elif json_data is not None:
                    resp = self.session_factory.post(url, json=json_data, timeout=self.timeout, headers=headers)
                else:
                    resp = self.session_factory.post(url, data=data, timeout=self.timeout, headers=headers)
            else:
                resp = self.session_factory.request(method, url, timeout=self.timeout, headers=headers)
        except requests.exceptions.Timeout:
            elapsed = time.time() - req_start
            return {
                "method": method,
                "url": url,
                "status_code": 0,
                "ok": False,
                "headers": {},
                "body": "",
                "elapsed_sec": elapsed,
                "error": "timeout",
            }
        except requests.exceptions.RequestException as exc:
            elapsed = time.time() - req_start
            return {
                "method": method,
                "url": url,
                "status_code": 0,
                "ok": False,
                "headers": {},
                "body": "",
                "elapsed_sec": elapsed,
                "error": str(exc),
            }
        elapsed = time.time() - req_start

        body_text = ""
        try:
            body_text = resp.text
        except Exception:
            body_text = ""

        return {
            "method": method,
            "url": url,
            "status_code": resp.status_code,
            "ok": resp.ok,
            "headers": dict(resp.headers),
            "body": body_text,
            "elapsed_sec": elapsed,
            "error": None,
        }

    # ------------------------------------------------------------------
    # File upload
    # ------------------------------------------------------------------

    def inject_file_upload(
        self,
        url: str,
        form_fields: List[Dict[str, str]],
        file_field_name: str,
        file_info: Dict[str, str],
    ) -> Dict[str, Any]:
        """Multipart POST with a file in the specified field."""
        self._apply_session_to_factory()
        headers = self.session.get_request_headers()

        # Build multipart files dict
        file_bytes = file_info["content"]
        if isinstance(file_bytes, str):
            file_bytes = file_bytes.encode("utf-8")
        files = {
            file_field_name: (file_info["filename"], file_bytes, file_info.get("content_type", "application/octet-stream"))
        }

        # Other form fields
        data: Dict[str, str] = {}
        for f in form_fields:
            if f["name"] != file_field_name:
                data[f["name"]] = f.get("value", "")

        data = self.session.attach_csrf_to_data(data)

        req_start = time.time()
        try:
            resp = self.session_factory.post(
                url, files=files, data=data, timeout=self.timeout, headers=headers
            )
        except requests.exceptions.RequestException as exc:
            elapsed = time.time() - req_start
            return {
                "method": "POST",
                "url": url,
                "status_code": 0,
                "ok": False,
                "headers": {},
                "body": "",
                "elapsed_sec": elapsed,
                "error": str(exc),
                "files_sent": file_info["filename"],
            }

        elapsed = time.time() - req_start
        body_text = ""
        try:
            body_text = resp.text
        except Exception:
            body_text = ""

        return {
            "method": "POST",
            "url": url,
            "status_code": resp.status_code,
            "ok": resp.ok,
            "headers": dict(resp.headers),
            "body": body_text,
            "elapsed_sec": elapsed,
            "error": None,
            "files_sent": file_info["filename"],
        }

    # ------------------------------------------------------------------
    # Baseline
    # ------------------------------------------------------------------

    def get_baseline(self, url: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Get a clean baseline response for a URL (no payload)."""
        if params:
            qs = urlencode(params, doseq=True)
            separator = "&" if "?" in url else "?"
            full_url = f"{url}{separator}{qs}"
        else:
            full_url = url
        return self._send_request("GET", full_url)
