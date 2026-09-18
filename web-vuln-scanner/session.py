"""
Session management — captures cookies/tokens from the browser and applies
them to raw HTTP requests so tests run in the same authenticated context.
"""

from typing import Dict, Optional


class SessionManager:
    """Holds cookies, headers, and token state extracted from the browser."""

    def __init__(self) -> None:
        self.cookies: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}
        self.base_url: str = ""
        self.csrf_token: Optional[str] = None
        self.csrf_param_name: str = "csrfToken"
        self.jwt_token: Optional[str] = None
        self.auth_state: str = "unknown"  # unknown | anonymous | authenticated

    def set_base_url(self, url: str) -> None:
        self.base_url = url.rstrip("/")

    def set_cookies(self, cookie_dict: Dict[str, str]) -> None:
        """Update cookies from browser context."""
        self.cookies.update(cookie_dict)

    def set_headers(self, header_dict: Dict[str, str]) -> None:
        """Store common headers (User-Agent, etc.) for raw requests."""
        self.headers.update(header_dict)

    def set_csrf_token(self, token: str, param_name: str = "csrfToken") -> None:
        self.csrf_token = token
        self.csrf_param_name = param_name

    def set_jwt_token(self, token: str) -> None:
        self.jwt_token = token

    def set_auth_state(self, state: str) -> None:
        self.auth_state = state

    def get_request_cookies(self) -> Dict[str, str]:
        """Return cookies formatted for `requests` library."""
        return dict(self.cookies)

    def get_request_headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Return headers for raw HTTP requests, merged with extras."""
        h = dict(self.headers)
        if extra:
            h.update(extra)
        return h

    def get_headers_forAjax(self) -> Dict[str, str]:
        """Headers that mimic an XHR/fetch request."""
        h = self.get_request_headers({
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/plain, */*",
        })
        return h

    def attach_csrf_to_data(self, data: Dict[str, str]) -> Dict[str, str]:
        """Insert CSRF token into form POST data if known."""
        if self.csrf_token:
            data[self.csrf_param_name] = self.csrf_token
        return data

    def attach_csrf_to_form_data(
        self, form_data: Dict[str, str]
    ) -> Dict[str, str]:
        """Same as attach_csrf_to_data but semantically for multipart forms."""
        return self.attach_csrf_to_data(form_data)

    def to_dict(self) -> Dict:
        """Serialize session state for debugging / reporting."""
        return {
            "base_url": self.base_url,
            "auth_state": self.auth_state,
            "cookie_count": len(self.cookies),
            "csrf_token_set": self.csrf_token is not None,
            "jwt_token_set": self.jwt_token is not None,
            "cookies": dict(self.cookies),
            "headers": dict(self.headers),
        }

    def __repr__(self) -> str:
        return (
            f"SessionManager(base_url={self.base_url!r}, "
            f"auth={self.auth_state!r}, cookies={len(self.cookies)}, "
            f"csrf={'yes' if self.csrf_token else 'no'})"
        )
