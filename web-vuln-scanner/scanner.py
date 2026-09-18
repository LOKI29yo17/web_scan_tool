"""
Scanner — main entry point.
Wires together crawler, session, injector, and analyzer to test a target
for XSS, SQL injection, path traversal, and file upload vulnerabilities.

Usage:
    python3 -m web_vuln_scanner.scanner --url http://localhost:3000
    python3 -m web_vuln_scanner.scanner --url http://localhost:3000 --no-crawl
    python3 -m web_vuln_scanner.scanner --url http://localhost:3000 --auth test@juice.com / Juice123
"""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# When run directly, add this directory to path so imports work
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import crawler
import session
import injector
import payloads
import analyzer
import auth_analyzer

from crawler import Crawler
from session import SessionManager
from injector import Injector
from payloads import get_payloads
from analyzer import (
    analyze_xss,
    analyze_sqli_error,
    analyze_sqli_time,
    analyze_sqli_boolean,
    analyze_path_traversal,
    analyze_file_upload,
    consolidate_findings,
)
from auth_analyzer import run_access_control_tests


class Scanner:
    """Main scanner orchestrator."""

    def __init__(
        self,
        base_url: str,
        do_crawl: bool = True,
        username: Optional[str] = None,
        password: Optional[str] = None,
        session_cookie: Optional[str] = None,
        report_dir: str = "reports",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.do_crawl = do_crawl
        self.username = username
        self.password = password.strip() if password else None
        self.session_cookie = session_cookie
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)

        self.session = SessionManager()
        self.session.set_base_url(self.base_url)
        self.injector: Optional[Injector] = None
        self.endpoints: List[Any] = []
        self.findings: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Crawl phase
    # ------------------------------------------------------------------

    def run_crawl(self) -> None:
        print(f"\n{'='*60}")
        print(f"PHASE 1: CRAWLING {self.base_url}")
        print(f"{'='*60}\n")
        crawler = Crawler(self.base_url, self.session)
        self.endpoints = crawler.run(max_pages=30)

        report_path = self.report_dir / "crawl_report.json"
        crawler.save_report(str(report_path))

        # Refresh injector with discovered cookies
        if self.injector:
            self.injector.refresh()

        print(f"\n[crawl] Discovered {len(self.endpoints)} endpoints")
        for ep in self.endpoints[:10]:
            print(f"  - {ep.method} {ep.url}")
        if len(self.endpoints) > 10:
            print(f"  ... and {len(self.endpoints) - 10} more")

    # ------------------------------------------------------------------
    # Login helper — tries API first, falls back to browser UI
    # ------------------------------------------------------------------

    def try_login(self) -> bool:
        """Attempt login: API first, then browser UI if API fails."""
        if not self.username or not self.password:
            return False

        # Step 1: try API login
        print(f"\n[login] Attempting API login as {self.username}")
        if self._try_api_login():
            return True

        print(f"[login] API login failed — trying browser login")
        # Step 2: try browser UI login (requires crawler context)
        if self._try_browser_login():
            return True

        print(f"[login] All login methods failed")
        return False

    def _try_api_login(self) -> bool:
        """Attempt login via HTTP API (JSON + form-encoded)."""
        import injector as injector_mod
        inj = injector_mod.Injector(self.session, timeout_sec=15)
        login_url = f"{self.base_url}/rest/user/login"
        import json as json_mod

        # Try JSON POST
        resp = inj.inject_post_json(login_url, {"email": self.username, "password": self.password}, "email", self.password)
        if resp.get("status_code") == 200:
            return self._process_login_response(resp, "JSON")

        # Try form-encoded POST
        resp2 = inj._send_request("POST", login_url,
                                   data={"email": self.username, "password": self.password})
        return self._process_login_response(resp2, "form-encoded")

    def _try_browser_login(self) -> bool:
        """Attempt login via the browser UI (Playwright)."""
        from playwright.sync_api import sync_playwright

        print(f"[login] Opening browser to {self.base_url}/#/login")

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()

            # Navigate to login page
            page.goto(f"{self.base_url}/#/login", wait_until="domcontentloaded", timeout=15000)
            time.sleep(2)

            # Fill email field
            try:
                email_input = page.locator('input[type="email"], input[name="email"], input#email')
                email_input.fill(self.username)
            except Exception as exc:
                print(f"[login] Could not find email field: {exc}")
                browser.close()
                return False

            # Fill password field
            try:
                pass_input = page.locator('input[type="password"], input[name="password"], input#password')
                pass_input.fill(self.password)
            except Exception as exc:
                print(f"[login] Could not find password field: {exc}")
                browser.close()
                return False

            # Click login button
            try:
                page.locator('button[type="submit"], button:has-text("Login"), button:has-text("Sign In")').first.click()
                time.sleep(3)
            except Exception as exc:
                print(f"[login] Could not click login button: {exc}")
                browser.close()
                return False

            # Capture cookies and JWT
            cookies = []
            jwt = None
            try:
                cookies = context.cookies()
            except Exception:
                pass

            # Check localStorage first
            try:
                jwt = page.evaluate(
                    "() => localStorage.getItem('jwt') || localStorage.getItem('token') || localStorage.getItem('accessToken')"
                )
            except Exception:
                pass

            # Check cookies for JWT if not found in localStorage
            if not jwt:
                for c in cookies:
                    if c.get("name") and c.get("value"):
                        name_lower = c["name"].lower()
                        if any(term in name_lower for term in ["jwt", "token", "auth", "session"]):
                            val = c["value"]
                            if val and len(val) > 20:
                                jwt = val
                                break

            if jwt:
                print(f"[login] Browser login success — JWT captured")
                self.session.set_jwt_token(jwt)
                self.session.set_auth_state("authenticated")
                browser.close()
                return True

            # Still capture regular cookies
            for c in cookies:
                if c.get("name") and c.get("value") and len(c.get("value", "")) > 10:
                    self.session.cookies[c["name"]] = c["value"]

            # Check if we're on a logged-in page
            current_url = page.url
            if "/login" not in current_url and "/#/login" not in current_url:
                print(f"[login] Browser login may have succeeded — redirected to {current_url}")
                self.session.set_auth_state("authenticated")
                browser.close()
                return True

            print(f"[login] Browser login did not succeed — still at {current_url}")
            browser.close()
            return False
            return False

    def _process_login_response(self, resp: Dict[str, Any], method: str) -> bool:
        """Process a login response and capture JWT if successful."""
        if resp.get("status_code") != 200 or not resp.get("body"):
            print(f"[login] Failed via {method} — status {resp.get('status_code')}")
            return False

        import json as json_mod
        try:
            data = json_mod.loads(resp["body"])
        except json_mod.JSONDecodeError:
            print(f"[login] Non-JSON response via {method}: {resp['body'][:100]}")
            return False

        jwt = data.get("token") or data.get("accessToken") or data.get("jwt") or data.get("access_token")
        if jwt:
            self.session.set_jwt_token(jwt)
            self.session.set_auth_state("authenticated")
            print(f"[login] Success via {method} — JWT token captured")
            if self.injector:
                self.injector.refresh()
            return True

        # 200 but no JWT — might still be logged in via session cookie
        print(f"[login] {method} returned 200 but no JWT found in response")
        # Check if new cookies were set
        if len(self.session.cookies) > 0:
            self.session.set_auth_state("authenticated")
            print(f"[login] Session cookies captured via {method}")
            if self.injector:
                self.injector.refresh()
            return True

        print(f"[login] Failed via {method}")
        return False

    # ------------------------------------------------------------------
    # Testing phase
    # ------------------------------------------------------------------

    def run_tests(self) -> None:
        print(f"\n{'='*60}")
        print("PHASE 2: VULNERABILITY TESTING")
        print(f"{'='*60}\n")

        # Initialize injector
        self.injector = Injector(self.session, timeout_sec=20)

        if self.username and self.password:
            self.try_login()

        # Group endpoints by test type
        get_endpoints = [e for e in self.endpoints if e.method == "GET" and e.inputs]
        post_forms = [e for e in self.endpoints if e.method == "POST"]
        upload_endpoints = [e for e in self.endpoints if e.has_file_upload]

        print(f"[test] GET endpoints with params: {len(get_endpoints)}")
        print(f"[test] POST forms: {len(post_forms)}")
        print(f"[test] File upload endpoints: {len(upload_endpoints)}")

        # --- XSS tests ---
        self._test_xss(get_endpoints, post_forms)

        # --- SQLi tests ---
        self._test_sqli(get_endpoints, post_forms)

        # --- Path traversal tests ---
        self._test_path_traversal(get_endpoints)

        # --- File upload tests ---
        self._test_file_upload(upload_endpoints, post_forms)

        # --- Access control / authentication tests ---
        self._test_access_control()

        # Deduplicate
        self.findings = consolidate_findings(self.findings)

    def _test_xss(self, get_eps: List, post_forms: List) -> None:
        print(f"\n--- XSS Testing ---")
        xss_payloads = get_payloads("xss")
        xss_inject_payloads = get_payloads("xss_injection")

        all_xss = xss_payloads + xss_inject_payloads

        # Test GET parameters
        for ep in get_eps[:15]:  # limit per endpoint type to keep runtime reasonable
            for inp in ep.inputs:
                if inp["type"] not in ("url_param", "text"):
                    continue
                for p in all_xss:
                    resp = self.injector.inject_get(ep.url, inp["name"], p["payload"])
                    finding = analyze_xss(
                        p["name"], p["payload"], resp, ep.url, inp["name"], p.get("type", "reflected")
                    )
                    if finding:
                        self.findings.append(finding)
                        print(f"[XSS] {finding['confidence']:6s} | {ep.url} | {inp['name']} | {p['name']}")

        # Test POST forms
        for ep in post_forms[:10]:
            for inp in ep.inputs:
                if inp["type"] in ("file", "submit", "button", "hidden"):
                    continue
                for p in all_xss[:8]:  # fewer payloads per field
                    resp = self.injector.inject_post_form(
                        ep.form_action or ep.url,
                        ep.inputs,
                        inp["name"],
                        p["payload"],
                    )
                    finding = analyze_xss(
                        p["name"], p["payload"], resp, ep.form_action or ep.url, inp["name"], p.get("type", "reflected")
                    )
                    if finding:
                        self.findings.append(finding)
                        print(f"[XSS] {finding['confidence']:6s} | {ep.form_action or ep.url} | {inp['name']} | {p['name']}")

        print(f"[XSS] Done. {sum(1 for f in self.findings if f['vulnerability'] == 'XSS')} potential findings.")

    def _test_sqli(self, get_eps: List, post_forms: List) -> None:
        print(f"\n--- SQLi Testing ---")

        # Collect payloads
        bypass = get_payloads("sqli_bypass")
        error_payloads = get_payloads("sqli_error")
        time_payloads = get_payloads("sqli_time")
        boolean_true = [p for p in get_payloads("sqli_boolean") if p.get("condition") == "true"]
        boolean_false = [p for p in get_payloads("sqli_boolean") if p.get("condition") == "false"]
        union_payloads = get_payloads("sqli_union")

        # Test GET parameters
        for ep in get_eps[:15]:
            for inp in ep.inputs:
                if inp["type"] not in ("url_param", "text"):
                    continue

                # Baseline
                baseline = self.injector.get_baseline(ep.url, {inp["name"]: "test"})

                for p in bypass + error_payloads[:4]:
                    resp = self.injector.inject_get(ep.url, inp["name"], p["payload"])
                    finding = analyze_sqli_error(
                        p["name"], p["payload"], resp, ep.url, inp["name"]
                    )
                    if finding:
                        self.findings.append(finding)
                        print(f"[SQLi] {finding['confidence']:6s} | {ep.url} | {inp['name']} | {p['name']} | {finding.get('subtype','')}")

                # Boolean-based only (skip time-based — too slow for initial scan)
                if boolean_true and boolean_false:
                    resp_t = self.injector.inject_get(ep.url, inp["name"], boolean_true[0]["payload"])
                    resp_f = self.injector.inject_get(ep.url, inp["name"], boolean_false[0]["payload"])
                    finding = analyze_sqli_boolean(
                        boolean_true[0]["name"], boolean_true[0]["payload"],
                        resp_t, resp_f, ep.url, inp["name"]
                    )
                    if finding:
                        self.findings.append(finding)
                        print(f"[SQLi] {finding['confidence']:6s} | {ep.url} | {inp['name']} | boolean-based (diff {finding['evidence']['diff_ratio']})")

        # Test POST forms
        for ep in post_forms[:10]:
            for inp in ep.inputs:
                if inp["type"] in ("file", "submit", "button", "hidden"):
                    continue

                baseline = self.injector.inject_post_form(
                    ep.form_action or ep.url, ep.inputs, inp["name"], "test"
                )

                for p in bypass + error_payloads[:4]:
                    resp = self.injector.inject_post_form(
                        ep.form_action or ep.url, ep.inputs, inp["name"], p["payload"]
                    )
                    finding = analyze_sqli_error(
                        p["name"], p["payload"], resp, ep.form_action or ep.url, inp["name"]
                    )
                    if finding:
                        self.findings.append(finding)
                        print(f"[SQLi] {finding['confidence']:6s} | POST {ep.form_action or ep.url} | {inp['name']} | {p['name']}")

        print(f"[SQLi] Done. {sum(1 for f in self.findings if f['vulnerability'] == 'SQL Injection')} potential findings.")

    def _test_path_traversal(self, get_eps: List) -> None:
        print(f"\n--- Path Traversal Testing ---")
        payloads = get_payloads("path_traversal")

        # Target endpoints that look like they might read files
        # (URL contains 'file', 'download', 'export', 'image', 'avatar', 'path', 'read')
        file_keywords = ["file", "download", "export", "image", "avatar", "path", "read", "asset", "static"]

        candidates = []
        for ep in get_eps:
            url_lower = ep.url.lower()
            if any(kw in url_lower for kw in file_keywords):
                candidates.append(ep)
        if not candidates:
            candidates = get_eps[:10]  # fallback — test a sample anyway

        for ep in candidates[:10]:
            for inp in ep.inputs:
                if inp["type"] not in ("url_param", "text"):
                    continue
                for p in payloads[:12]:  # limit per endpoint
                    resp = self.injector.inject_get(ep.url, inp["name"], p["payload"])
                    finding = analyze_path_traversal(
                        p["name"], p["payload"], resp, ep.url, inp["name"]
                    )
                    if finding:
                        self.findings.append(finding)
                        print(f"[PathTraversal] {finding['confidence']:6s} | {ep.url} | {inp['name']} | {p['name']} | {finding.get('target_file','')}")

        print(f"[PathTraversal] Done. {sum(1 for f in self.findings if f['vulnerability'] == 'Path Traversal')} potential findings.")

    def _test_file_upload(self, upload_eps: List, post_forms: List) -> None:
        print(f"\n--- File Upload Testing ---")
        tests = get_payloads("file_upload")

        targets = upload_eps if upload_eps else post_forms[:5]

        for ep in targets[:5]:
            # Find the file input field
            file_field = None
            other_fields = []
            for inp in ep.inputs:
                if inp["type"] == "file":
                    file_field = inp
                else:
                    other_fields.append(inp)

            if not file_field and ep.has_file_upload:
                # Assume first text input is the file field placeholder
                file_field = {"name": "file", "type": "file"}
                other_fields = [i for i in ep.inputs if i["type"] != "file"]

            if not file_field:
                continue

            field_name = file_field["name"]

            for t in tests[:5]:  # limit per endpoint to keep runtime sane
                file_info = {
                    "filename": t["filename"],
                    "content": t["content"],
                    "content_type": t.get("content_type", "application/octet-stream"),
                }
                resp = self.injector.inject_file_upload(
                    ep.form_action or ep.url,
                    ep.inputs,
                    field_name,
                    file_info,
                )
                findings = analyze_file_upload(t["name"], file_info, resp, ep.form_action or ep.url)
                for f in findings:
                    self.findings.append(f)
                    print(f"[Upload] {f['confidence']:6s} | {f['vulnerability']} | {f.get('subtype','')} | {ep.form_action or ep.url} | {f.get('filename_tested','')}")

        print(f"[Upload] Done. {sum(1 for f in self.findings if f['vulnerability'] in ('File Upload','Unrestricted File Upload'))} potential findings.")

    # ------------------------------------------------------------------
    # Access control / authentication tests
    # ------------------------------------------------------------------

    def _test_access_control(self) -> None:
        """Run access control and authentication vulnerability tests."""
        print(f"\n--- Access Control / Auth Testing ---")

        # Extract JWT from session for analysis
        jwt_token = self.session.jwt_token

        # Run access control tests (lightweight — no login required)
        auth_findings = run_access_control_tests(
            injector=self.injector,
            session=self.session,
            base_url=self.base_url,
            login_url=f"{self.base_url}/rest/user/login",
            jwt_token=jwt_token,
            own_email=self.username,
            discovered_endpoints=self.endpoints,
            skip_idor=True,          # needs JWT — skip if login failed
            skip_weak_creds=True,    # already tried login
            skip_enum=True,          # not a Juice Shop focus
            skip_unauth=False,       # test unauthenticated access to protected endpoints
            skip_priv_esc=False,     # test admin endpoint patterns
        )

        for f in auth_findings:
            self.findings.append(f)
            conf = f.get('confidence', 'unknown')
            vtype = f.get('vulnerability', 'Unknown')
            subtype = f.get('subtype', '')
            endpoint = f.get('endpoint', f.get('login_url', ''))
            print(f"[{conf:6s}] {vtype:30s} | {subtype[:40]:40s} | {endpoint[:60]}")

        ac_count = sum(1 for f in auth_findings
                       if f['vulnerability'] in ('Broken Access Control', 'Authentication', 'Session Management', 'Sensitive Data Exposure'))
        print(f"[AccessControl] Done. {ac_count} potential findings.")

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def save_report(self) -> str:
        """Write the final report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.report_dir / f"scan_report_{timestamp}.json"

        report = {
            "target": self.base_url,
            "scan_time": datetime.now().isoformat(),
            "crawl_done": self.do_crawl,
            "auth_attempted": bool(self.username and self.password),
            "total_findings": len(self.findings),
            "findings_by_type": self._count_by_type(),
            "findings": self.findings,
        }

        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n{'='*60}")
        print("SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"Target:      {self.base_url}")
        print(f"Findings:    {len(self.findings)}")
        for vtype, count in report["findings_by_type"].items():
            print(f"  {vtype}: {count}")
        print(f"\nReport: {report_path}")
        return str(report_path)

    def _count_by_type(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            v = f.get("vulnerability", "Unknown")
            counts[v] = counts.get(v, 0) + 1
        return counts

    def print_summary(self) -> None:
        """Print a human-readable summary to stdout."""
        if not self.findings:
            print("\nNo potential findings detected.")
            return

        print(f"\n{'='*60}")
        print("FINDINGS SUMMARY")
        print(f"{'='*60}\n")

        for i, f in enumerate(self.findings, 1):
            vtype = f.get("vulnerability", "Unknown")
            subtype = f.get("subtype", "")
            endpoint = f.get("endpoint", "")
            param = f.get("parameter", "")
            confidence = f.get("confidence", "unknown")
            payload_name = f.get("payload_name", "")
            evidence = f.get("evidence", {})

            print(f"[{i}] {vtype} ({subtype})")
            print(f"    Confidence: {confidence}")
            print(f"    Endpoint:   {endpoint}")
            if param:
                print(f"    Parameter:  {param}")
            if payload_name:
                print(f"    Payload:    {payload_name}")
            if evidence:
                for k, val in evidence.items():
                    if isinstance(val, str) and len(val) > 120:
                        val = val[:120] + "..."
                    print(f"    {k}: {val}")
            print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Automated web vulnerability scanner — tests for XSS, SQLi, path traversal, and file upload issues."
    )
    parser.add_argument("--url", required=True, help="Target URL (e.g. http://localhost:3000)")
    parser.add_argument("--no-crawl", action="store_true", help="Skip crawling; test only explicitly provided endpoints")
    parser.add_argument("--auth", nargs=2, metavar=("USERNAME", "PASSWORD"), help="Login credentials (e.g. --auth user pass)")
    parser.add_argument("--cookie", help="Pre-existing session cookie (skips login)")
    parser.add_argument("--report-dir", default="reports", help="Directory for reports")
    parser.add_argument("--max-pages", type=int, default=30, help="Max pages to crawl")

    args = parser.parse_args()

    print(f"\n{'#'*60}")
    print(f"# WEB VULNERABILITY SCANNER")
    print(f"# Target: {args.url}")
    print(f"# {'Crawl: ON' if not args.no_crawl else 'Crawl: OFF'}")
    if args.auth:
        print(f"# Auth: {args.auth[0]} / ********")
    print(f"{'#'*60}\n")

    start = time.time()

    scanner = Scanner(
        base_url=args.url,
        do_crawl=not args.no_crawl,
        username=args.auth[0] if args.auth else None,
        password=args.auth[1] if args.auth else None,
        session_cookie=args.cookie,
        report_dir=args.report_dir,
    )

    if args.no_crawl:
        print("[scan] Crawling skipped — no endpoints to test unless provided manually.")
        print("[scan] Use --no-crawl only if you pass explicit endpoints in the code.")
        return

    scanner.run_crawl()
    scanner.run_tests()
    scanner.print_summary()
    report_path = scanner.save_report()

    elapsed = time.time() - start
    print(f"\nElapsed: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
