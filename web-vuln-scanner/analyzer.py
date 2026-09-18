"""
Analyzer — detection logic for each vulnerability class.
Takes a response snapshot and determines whether it indicates a finding.
"""

import re
import hashlib
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import payloads

from payloads import (
    PATH_TRAVERSAL_SIGNATURES,
)


# ---------------------------------------------------------------------------
# XSS detection
# ---------------------------------------------------------------------------

XSS_MARKER_PATTERNS = [
    "alert(1)",
    "alert('XSS-STORED-TEST')",
    "XSS_TEST_MARKER",
    "XSS_MARKER",
    "alert(document.cookie)",
    "prompt('XSS_TEST')",
    "confirm('XSS_TEST')",
]

XSS_EVENT_HANDLER_PATTERNS = [
    r'on\w+\s*=',
    r'javascript:',
]

SQLI_ERROR_PATTERNS = [
    # MySQL
    (r"SQL syntax.*MySQL", "mysql"),
    (r"Warning.*mysql_", "mysql"),
    (r"MySQLdb\.", "mysql"),
    (r"FATAL.*database.*", "generic"),
    (r"ORA-\d{5}", "oracle"),
    (r"PostgreSQL.*ERROR", "postgresql"),
    (r"pg_query", "postgresql"),
    (r"sqlite3\.", "sqlite"),
    (r"SQLite format 3", "sqlite"),
    (r"Unclosed quotation mark", "generic"),
    (r"java\.sql\.SQLException", "java"),
    (r"Microsoft SQL Server", "mssql"),
    (r"SqlException", "mssql"),
    (r"datetime conversion", "mssql"),
    (r"ODBC SQL Server", "mssql"),
    (r"pg_fetch", "postgresql"),
    (r"mysql_fetch", "mysql"),
    (r"mysqli_", "mysql"),
    (r"PDOException", "generic"),
    (r"Query failed", "generic"),
    (r"error in your SQL syntax", "mysql"),
    (r"expects parameter", "generic"),
    (r"column .* doesn't exist", "generic"),
    (r"table .* doesn't exist", "generic"),
    (r"invalid column", "generic"),
    (r"syntax error", "generic"),
    (r"near ", "generic"),
]


def analyze_xss(
    payload_name: str,
    payload: str,
    response: Dict[str, Any],
    endpoint_url: str,
    param_name: str = "",
    context: str = "reflected",
) -> Optional[Dict[str, Any]]:
    """Check a response for reflected or executed XSS."""
    body = response.get("body", "")
    if not body:
        return None

    # Detection 1: payload reflected in body without proper escaping
    # Check for the literal payload or key fragments
    payload_fragments = _extract_xss_fragments(payload)
    reflected = False
    for frag in payload_fragments:
        if frag and frag in body:
            reflected = True
            break

    # Detection 2: known XSS markers present
    marker_hit = False
    for marker in XSS_MARKER_PATTERNS:
        if marker and marker in body:
            marker_hit = True
            break

    # Detection 3: event handler pattern in body (unsanitized)
    event_hit = False
    for pattern in XSS_EVENT_HANDLER_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            event_hit = True
            break

    # Heuristic: payload appears inside an executable context
    in_script = f"<script>{payload[:30]}" in body or f"<script>{payload}" in body
    in_attr = re.search(rf'{re.escape(payload[:20])}.*on\w+\s*=', body, re.IGNORECASE)

    findings = []
    if reflected:
        findings.append("payload_reflected")
    if marker_hit:
        findings.append("marker_detected")
    if event_hit:
        findings.append("event_handler_in_response")
    if in_script:
        findings.append("in_script_context")

    if not findings:
        return None

    # Confidence
    if marker_hit or in_script:
        confidence = "high"
    elif reflected and event_hit:
        confidence = "medium"
    elif reflected:
        confidence = "low"
    else:
        confidence = "low"

    return {
        "vulnerability": "XSS",
        "subtype": context,
        "endpoint": endpoint_url,
        "parameter": param_name,
        "payload_name": payload_name,
        "payload": payload,
        "evidence": {
            "findings": findings,
            "payload_reflected": reflected,
            "marker_hit": marker_hit,
            "event_handler_pattern": event_hit,
            "in_script_context": in_script,
        },
        "confidence": confidence,
        "response_status": response.get("status_code"),
        "response_body_snippet": body[:500],
    }


def _extract_xss_fragments(payload: str) -> List[str]:
    """Break a payload into detectable fragments."""
    fragments = []
    # Strip HTML tags for comparison
    import re as _re
    text_only = _re.sub(r"<[^>]+>", "", payload)
    if text_only and len(text_only) > 3:
        fragments.append(text_only)
    # Take key parts
    if "alert" in payload:
        idx = payload.find("alert")
        frag = payload[idx:idx+20]
        if frag:
            fragments.append(frag)
    if len(payload) > 10:
        fragments.append(payload[:10])
    return fragments


# ---------------------------------------------------------------------------
# SQL injection detection
# ---------------------------------------------------------------------------

def analyze_sqli_error(
    payload_name: str,
    payload: str,
    response: Dict[str, Any],
    endpoint_url: str,
    param_name: str = "",
) -> Optional[Dict[str, Any]]:
    """Detect SQLi via database error messages in the response."""
    body = response.get("body", "")
    if not body:
        return None

    for pattern, dbms in SQLI_ERROR_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            return {
                "vulnerability": "SQL Injection",
                "subtype": "error-based",
                "dbms": dbms,
                "endpoint": endpoint_url,
                "parameter": param_name,
                "payload_name": payload_name,
                "payload": payload,
                "evidence": {
                    "error_pattern": pattern,
                    "matched_text": _extract_context(body, pattern),
                },
                "confidence": "high",
                "response_status": response.get("status_code"),
                "response_body_snippet": body[:500],
            }
    return None


def analyze_sqli_time(
    payload_name: str,
    payload: str,
    response: Dict[str, Any],
    baseline_elapsed: float,
    endpoint_url: str,
    param_name: str = "",
    threshold_sec: float = 3.0,
) -> Optional[Dict[str, Any]]:
    """Detect time-based blind SQLi via response delay."""
    elapsed = response.get("elapsed_sec", 0)
    if elapsed <= 0:
        return None

    delay = elapsed - baseline_elapsed
    if delay >= threshold_sec:
        return {
            "vulnerability": "SQL Injection",
            "subtype": "time-based blind",
            "endpoint": endpoint_url,
            "parameter": param_name,
            "payload_name": payload_name,
            "payload": payload,
            "evidence": {
                "baseline_elapsed_sec": round(baseline_elapsed, 3),
                "payload_elapsed_sec": round(elapsed, 3),
                "delay_sec": round(delay, 3),
                "threshold_sec": threshold_sec,
            },
            "confidence": "medium",
            "response_status": response.get("status_code"),
        }
    return None


def analyze_sqli_boolean(
    payload_name: str,
    payload: str,
    response_true: Dict[str, Any],
    response_false: Dict[str, Any],
    endpoint_url: str,
    param_name: str = "",
) -> Optional[Dict[str, Any]]:
    """Detect boolean-based blind SQLi via content difference."""
    body_true = response_true.get("body", "")
    body_false = response_false.get("body", "")

    if not body_true or not body_false:
        return None

    # Hash comparison
    hash_true = hashlib.md5(body_true.encode("utf-8", errors="replace")).hexdigest()
    hash_false = hashlib.md5(body_false.encode("utf-8", errors="replace")).hexdigest()

    if hash_true == hash_false:
        return None  # no difference — not a finding via this method

    # Calculate diff ratio
    min_len = min(len(body_true), len(body_false))
    if min_len == 0:
        return None

    # Simple character diff
    diff_count = sum(1 for a, b in zip(body_true, body_false) if a != b)
    diff_ratio = diff_count / min_len if min_len > 0 else 0

    return {
        "vulnerability": "SQL Injection",
        "subtype": "boolean-based blind",
        "endpoint": endpoint_url,
        "parameter": param_name,
        "payload_name": payload_name,
        "payload": payload,
        "evidence": {
            "true_response_hash": hash_true,
            "false_response_hash": hash_false,
            "diff_ratio": round(diff_ratio, 3),
            "true_body_length": len(body_true),
            "false_body_length": len(body_false),
        },
        "confidence": "medium" if diff_ratio > 0.05 else "low",
        "response_status_true": response_true.get("status_code"),
        "response_status_false": response_false.get("status_code"),
    }


def _extract_context(text: str, pattern: str, window: int = 80) -> str:
    """Extract a snippet of text around a regex match."""
    match = re.search(pattern, text, re.IGNORECASE)
    if not match:
        return ""
    start = max(0, match.start() - window)
    end = min(len(text), match.end() + window)
    return text[start:end].replace("\n", " ")[:200]


# ---------------------------------------------------------------------------
# Path traversal detection
# ---------------------------------------------------------------------------

def analyze_path_traversal(
    payload_name: str,
    payload: str,
    response: Dict[str, Any],
    endpoint_url: str,
    param_name: str = "",
) -> Optional[Dict[str, Any]]:
    """Detect path traversal via file content signatures in the response."""
    body = response.get("body", "")
    if not body:
        return None

    status = response.get("status_code", 0)

    # Detection 1: known file content signatures (require 2+ matches)
    for target_file, signatures in PATH_TRAVERSAL_SIGNATURES.items():
        found = sum(1 for sig in signatures if sig in body)
        if found >= 2:
            matched = [sig for sig in signatures if sig in body][:2]
            return {
                "vulnerability": "Path Traversal",
                "subtype": "file disclosure",
                "target_file": target_file,
                "endpoint": endpoint_url,
                "parameter": param_name,
                "payload_name": payload_name,
                "payload": payload,
                "evidence": {
                    "signatures_matched": matched,
                    "target_file": target_file,
                    "status_code": status,
                    "signature_count": found,
                },
                "confidence": "high",
                "response_body_snippet": body[:500],
            }

    # Detection 2: status 200 with response that looks like a file
    # (heuristic: response body doesn't resemble an HTML error page)
    if status == 200 and len(body) > 50:
        # If body doesn't contain typical HTML error indicators
        html_error_indicators = ["404", "not found", "error", "forbidden", "denied"]
        has_html_error = any(ind in body.lower() for ind in html_error_indicators)
        if not has_html_error and len(body) > 200:
            # Weak signal — only report as low confidence
            return {
                "vulnerability": "Path Traversal",
                "subtype": "possible file disclosure",
                "endpoint": endpoint_url,
                "parameter": param_name,
                "payload_name": payload_name,
                "payload": payload,
                "evidence": {
                    "status_code": status,
                    "body_length": len(body),
                    "no_html_error_indicators": True,
                },
                "confidence": "low",
                "response_body_snippet": body[:200],
            }

    return None


# ---------------------------------------------------------------------------
# File upload detection
# ---------------------------------------------------------------------------

UPLOAD_SUCCESS_INDICATORS = [
    "upload successful",
    "file uploaded",
    "upload complete",
    "uploaded",
    "success",
    "accepted",
]

UPLOAD_REJECT_INDICATORS = [
    "not allowed",
    "invalid file type",
    "disallowed",
    "forbidden extension",
    "rejected",
    "unsupported",
]


def analyze_file_upload(
    test_name: str,
    file_info: Dict[str, str],
    response: Dict[str, Any],
    endpoint_url: str,
) -> List[Dict[str, Any]]:
    """Analyze a file upload response for findings."""
    findings = []
    body = response.get("body", "").lower()
    status = response.get("status_code", 0)
    filename = file_info.get("filename", "")

    # Did the upload succeed?
    success = False
    for ind in UPLOAD_SUCCESS_INDICATORS:
        if ind in body:
            success = True
            break
    if status in (200, 201, 204) and response.get("ok"):
        success = True

    # Did the server reject it?
    rejected = False
    for ind in UPLOAD_REJECT_INDICATORS:
        if ind in body:
            rejected = True
            break

    # 1. Extension allowed that should be blocked
    dangerous_exts = [".php", ".phtml", ".php5", ".asp", ".aspx", ".jsp", ".exe", ".sh", ".py"]
    allowed_dangerous = False
    for ext in dangerous_exts:
        if filename.lower().endswith(ext):
            if success and not rejected:
                allowed_dangerous = True
                findings.append({
                    "vulnerability": "Unrestricted File Upload",
                    "subtype": "dangerous extension accepted",
                    "extension": ext,
                    "endpoint": endpoint_url,
                    "filename_tested": filename,
                    "evidence": {
                        "status_code": status,
                        "upload_accepted": success,
                        "server_rejected": rejected,
                        "response_body_snippet": response.get("body", "")[:300],
                    },
                    "confidence": "high" if success else "low",
                })

    # 2. Content-type spoofing
    if success and not rejected:
        ct = file_info.get("content_type", "")
        if ct.startswith("image/") or ct == "text/plain":
            if any(filename.lower().endswith(ext) for ext in dangerous_exts):
                findings.append({
                    "vulnerability": "File Upload",
                    "subtype": "content-type spoofing",
                    "endpoint": endpoint_url,
                    "filename_tested": filename,
                    "spoofed_content_type": ct,
                    "evidence": {
                        "status_code": status,
                        "upload_accepted": success,
                        "content_type_sent": ct,
                    },
                    "confidence": "medium",
                })

    # 3. SVG with script
    if filename.lower().endswith(".svg"):
        if success and not rejected:
            findings.append({
                "vulnerability": "File Upload",
                "subtype": "SVG upload with script",
                "endpoint": endpoint_url,
                "filename_tested": filename,
                "evidence": {
                    "status_code": status,
                    "upload_accepted": success,
                },
                "confidence": "medium",
            })

    # 4. Double extension
    if ".." in filename or filename.lower().endswith(".php.jpg") or filename.lower().endswith(".jpg.php"):
        if success and not rejected:
            findings.append({
                "vulnerability": "File Upload",
                "subtype": "double extension bypass",
                "endpoint": endpoint_url,
                "filename_tested": filename,
                "evidence": {
                    "status_code": status,
                    "upload_accepted": success,
                },
                "confidence": "medium",
            })

    # 5. Upload succeeded but we need to check if the file is accessible
    # (this is a follow-up step, not done inline — record for later)
    if success and not rejected and filename:
        findings.append({
            "vulnerability": "File Upload",
            "subtype": "upload_successful_verify_access",
            "endpoint": endpoint_url,
            "filename_tested": filename,
            "evidence": {
                "status_code": status,
                "upload_accepted": True,
                "note": "Check if uploaded file is accessible via HTTP",
            },
            "confidence": "low",
        })

    return findings


# ---------------------------------------------------------------------------
# Consolidation
# ---------------------------------------------------------------------------

def consolidate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate and tier findings."""
    seen = set()
    result = []
    for f in findings:
        key = (
            f.get("vulnerability", ""),
            f.get("endpoint", ""),
            f.get("parameter", ""),
            f.get("payload_name", ""),
            f.get("subtype", ""),
        )
        key_str = str(key)
        if key_str in seen:
            continue
        seen.add(key_str)
        result.append(f)
    return result
