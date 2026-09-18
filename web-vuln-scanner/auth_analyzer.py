"""
Authentication and access control vulnerability testing.
Tests for: IDOR, broken authentication, JWT weaknesses, privilege escalation,
missing access control, username enumeration.
"""

import json
import base64
import re
import time
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# JWT analysis
# ---------------------------------------------------------------------------

def decode_jwt_part(part: str) -> Optional[Dict]:
    """Decode a base64url-encoded JWT part (no signature verification)."""
    try:
        padded = part + '=' * (4 - len(part) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded)
    except Exception:
        return None


def decode_jwt_headers(token: str) -> Optional[Dict]:
    """Decode JWT header without verification."""
    parts = token.split('.')
    if len(parts) >= 1:
        return decode_jwt_part(parts[0])
    return None


def decode_jwt_payload(token: str) -> Optional[Dict]:
    """Decode JWT payload without verification."""
    parts = token.split('.')
    if len(parts) >= 2:
        return decode_jwt_part(parts[1])
    return None


def analyze_jwt(token: str) -> List[Dict]:
    """Analyze a JWT token for security issues."""
    findings = []
    if not token:
        return findings

    headers = decode_jwt_headers(token)
    payload = decode_jwt_payload(token)

    # 1. Weak algorithm
    alg = headers.get('alg', '') if headers else ''
    if alg.lower() in ('none',):
        findings.append({
            'vulnerability': 'Authentication',
            'subtype': 'JWT algorithm "none"',
            'evidence': {'algorithm': alg, 'header': headers},
            'confidence': 'high',
        })

    # 2. kid header — potential key injection
    kid = headers.get('kid', '') if headers else ''
    if kid:
        findings.append({
            'vulnerability': 'Authentication',
            'subtype': 'JWT has kid header (potential key injection vector)',
            'evidence': {'kid': kid, 'header': headers},
            'confidence': 'low',
        })

    # 3. Sensitive data in payload
    if payload:
        sensitive_keys = ['password', 'secret', 'token', 'credit_card', 'ssn', 'key']
        for key, val in payload.items():
            key_lower = key.lower()
            for sensitive in sensitive_keys:
                if sensitive in key_lower and val:
                    findings.append({
                        'vulnerability': 'Sensitive Data Exposure',
                        'subtype': f'JWT payload contains "{key}"',
                        'evidence': {'key': key, 'value_preview': str(val)[:80]},
                        'confidence': 'medium',
                    })

    # 4. Missing expiration
    if payload and 'exp' not in payload and 'nbf' not in payload:
        findings.append({
            'vulnerability': 'Session Management',
            'subtype': 'JWT has no expiration (long-lived token)',
            'evidence': {'claims': list(payload.keys())},
            'confidence': 'medium',
        })

    # 5. Expired token
    if payload and 'exp' in payload:
        if payload['exp'] < time.time():
            findings.append({
                'vulnerability': 'Session Management',
                'subtype': 'JWT token is expired',
                'evidence': {'exp': payload['exp'], 'current_time': int(time.time())},
                'confidence': 'high',
            })

    # 6. Suspicious issuer
    if payload and 'iss' in payload:
        iss = payload['iss']
        if not iss or iss in ('/', ''):
            findings.append({
                'vulnerability': 'Authentication',
                'subtype': 'JWT issuer not properly set',
                'evidence': {'issuer': iss},
                'confidence': 'low',
            })

    # 7. Extract user identity from JWT (useful for IDOR testing)
    user_info: Dict[str, Any] = {}
    if payload:
        for key in ['sub', 'user', 'userid', 'user_id', 'id', 'email', 'name', 'role', 'role_admin', 'isadmin', 'admin']:
            if key in payload:
                user_info[key] = payload[key]
    if user_info:
        findings.append({
            'vulnerability': 'Informational',
            'subtype': 'JWT user identity extracted (for IDOR testing)',
            'evidence': {'user_claims': user_info},
            'confidence': 'info',
        })

    return findings


# ---------------------------------------------------------------------------
# IDOR detection
# ---------------------------------------------------------------------------

# Known Juice Shop REST endpoints that may have IDOR
JUICE_SHOP_IDOR_ENDPOINTS = [
    # Basket — known to be IDOR-vulnerable in Juice Shop
    {'url_tpl': '/rest/basket/{id}', 'method': 'GET', 'id_in': 'path',
     'description': 'Basket by ID'},
    # User profile — should only return own data
    {'url_tpl': '/rest/user', 'method': 'GET', 'id_in': 'none',
     'description': 'Current user profile'},
    # Wallet
    {'url_tpl': '/rest/user/wallet', 'method': 'GET', 'id_in': 'none',
     'description': 'User wallet'},
    # Address
    {'url_tpl': '/rest/address', 'method': 'GET', 'id_in': 'none',
     'description': 'User address'},
    # Orders (if endpoint exists)
    {'url_tpl': '/rest/order', 'method': 'GET', 'id_in': 'none',
     'description': 'Orders list'},
]

# Generic IDOR candidate patterns for any app
GENERIC_IDOR_PATTERNS = [
    (r'/api/users/[^/]+', 'user_id'),
    (r'/api/orders/[^/]+', 'order_id'),
    (r'/api/basket/[^/]+', 'basket_id'),
    (r'/api/account/[^/]+', 'account_id'),
    (r'/api/profile/[^/]+', 'profile_id'),
    (r'/api/documents/[^/]+', 'doc_id'),
    (r'/api/files/[^/]+', 'file_id'),
    (r'/api/messages/[^/]+', 'msg_id'),
    (r'/api/invoices/[^/]+', 'inv_id'),
    (r'/rest/users/[^/]+', 'user_id'),
    (r'/rest/orders/[^/]+', 'order_id'),
    (r'/rest/baskets/[^/]+', 'basket_id'),
]


def extract_emails_from_body(body: str) -> List[str]:
    """Extract email addresses from a response body."""
    emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', body)
    return list(set(emails))


def extract_ids_from_body(body: str) -> List[Dict[str, Any]]:
    """Extract potential ID values from a JSON response."""
    ids = []
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        # Try to find IDs in raw text
        id_matches = re.findall(r'"(id|ID|userId|userID|orderId|basketId|basket_id|user_id)[^:]*:\s*"?([^,"}\s]+)"?', body)
        for key, val in id_matches:
            ids.append({'key': key, 'value': val, 'type': 'text_extract'})
        return ids

    def search(obj, path=''):
        if isinstance(obj, dict):
            for key, val in obj.items():
                current_path = f'{path}.{key}' if path else key
                if isinstance(val, (str, int, float, bool)):
                    key_lower = key.lower()
                    if any(kw in key_lower for kw in [
                        'id', 'uuid', 'guid', 'oid', 'user', 'basket',
                        'order', 'account', 'profile', 'document', 'file',
                        'message', 'invoice', 'transaction', 'payment',
                        'email', 'name', 'firstName', 'lastName',
                    ]):
                        ids.append({
                            'path': current_path,
                            'key': key,
                            'value': str(val),
                            'type': 'json_field',
                        })
                elif isinstance(val, (dict, list)):
                    search(val, current_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                search(item, f'{path}[{i}]')

    search(data)
    return ids


def test_idor(
    injector: Any,
    session: Any,
    base_url: str,
    own_email: Optional[str] = None,
    own_user_id: Optional[str] = None,
) -> List[Dict]:
    """Test for IDOR vulnerabilities on known endpoints.

    Strategy:
    1. Get baseline responses for current user's resources
    2. Change IDs to other values and check if foreign data is returned
    """
    findings = []

    # Build test IDs to try — only 3 to keep runtime low
    test_ids = ['1', '2', '999'][:max_idor_ids]
    # Deduplicate
    test_ids = list(dict.fromkeys(test_ids))

    for ep in JUICE_SHOP_IDOR_ENDPOINTS:
        url_tpl = ep['url_tpl']
        method = ep['method']
        desc = ep['description']

        # Build URL
        if '{id}' in url_tpl:
            test_url = base_url.rstrip('/') + url_tpl.replace('{id}', test_ids[0])
        else:
            test_url = base_url.rstrip('/') + url_tpl

        # Get baseline
        baseline_resp = injector.inject_get_raw(test_url)

        if baseline_resp.get('status_code', 0) not in (200, 201, 204):
            continue  # Endpoint not accessible at all

        baseline_body = baseline_resp.get('body', '')
        baseline_emails = set(extract_emails_from_body(baseline_body))

        # Add own email if known
        if own_email:
            baseline_emails.add(own_email)

        # Test with other IDs
        for test_id in test_ids[1:]:  # skip first (used for baseline)
            if '{id}' in url_tpl:
                t_url = base_url.rstrip('/') + url_tpl.replace('{id}', test_id)
            else:
                t_url = test_url  # no ID in path

            resp = injector.inject_get_raw(t_url)
            status = resp.get('status_code', 0)

            if status not in (200, 201, 204):
                continue

            body = resp.get('body', '')
            test_emails = set(extract_emails_from_body(body))

            # Check for foreign emails
            foreign_emails = test_emails - baseline_emails
            if foreign_emails:
                findings.append({
                    'vulnerability': 'Broken Access Control',
                    'subtype': 'IDOR — access to other user\'s data',
                    'endpoint': t_url,
                    'description': desc,
                    'test_id_used': test_id,
                    'evidence': {
                        'status_code': status,
                        'own_emails': list(baseline_emails),
                        'returned_emails': list(test_emails),
                        'foreign_emails': list(foreign_emails),
                        'body_preview': body[:300],
                    },
                    'confidence': 'high',
                })
                continue

            # Check if response has different IDs than baseline
            baseline_ids = {i['value'] for i in extract_ids_from_body(baseline_body) if i['type'] == 'json_field'}
            test_ids_found = {i['value'] for i in extract_ids_from_body(body) if i['type'] == 'json_field'}

            if test_ids_found and baseline_ids:
                diff = test_ids_found - baseline_ids
                common = test_ids_found & baseline_ids
                # If most IDs are different → we're seeing different data
                if diff and len(diff) > len(common):
                    findings.append({
                        'vulnerability': 'Broken Access Control',
                        'subtype': 'IDOR — different resource IDs in response',
                        'endpoint': t_url,
                        'description': desc,
                        'test_id_used': test_id,
                        'evidence': {
                            'status_code': status,
                            'baseline_ids_sample': list(baseline_ids)[:5],
                            'test_ids_sample': list(test_ids_found)[:5],
                            'new_ids': list(diff)[:5],
                            'body_preview': body[:200],
                        },
                        'confidence': 'medium',
                    })

    return findings


# ---------------------------------------------------------------------------
# Authentication testing
# ---------------------------------------------------------------------------

WEAK_CREDENTIALS = [
    ('admin', 'admin'),
    ('admin', 'password'),
    ('admin', 'password1'),
    ('admin', 'admin123'),
    ('administrator', 'administrator'),
    ('root', 'root'),
    ('root', 'toor'),
    ('user', 'user'),
    ('test', 'test'),
    ('guest', 'guest'),
    ('administrator', 'password'),
    ('superadmin', 'superadmin'),
    ('demo', 'demo'),
    ('demo', 'demo123'),
    # Juice Shop specific
    ('admin@juice-shop.com', 'admin'),
    ('admin@juice-shop.com', 'password'),
    ('admin123@juice-shop.com', 'admin123'),
]


def test_weak_credentials(
    injector: Any,
    session: Any,
    login_url: str,
    username_field: str = 'email',
    password_field: str = 'password',
    max_attempts: int = 15,
) -> List[Dict]:
    """Test login with common weak credentials (small dictionary, not brute force)."""
    findings = []

    for username, password in WEAK_CREDENTIALS[:max_weak_creds]:
        payload = {username_field: username, password_field: password}
        resp = injector.inject_post_json(login_url, payload, username_field, password)

        status = resp.get('status_code', 0)
        body = resp.get('body', '')

        if status == 200 and resp.get('ok'):
            try:
                data = json.loads(body)
                token = data.get('token') or data.get('accessToken') or data.get('jwt') or data.get('access_token')
                if token:
                    findings.append({
                        'vulnerability': 'Broken Authentication',
                        'subtype': 'Weak credentials accepted',
                        'evidence': {
                            'username': username,
                            'password': password,
                            'login_url': login_url,
                            'token_received': True,
                            'token_preview': str(token)[:50],
                        },
                        'confidence': 'high',
                    })
                    break  # Stop after first success
            except json.JSONDecodeError:
                # 200 OK but not JSON — might still be a successful login
                if 'logout' in body.lower() or 'welcome' in body.lower() or 'dashboard' in body.lower():
                    findings.append({
                        'vulnerability': 'Broken Authentication',
                        'subtype': 'Weak credentials accepted (non-JSON response)',
                        'evidence': {
                            'username': username,
                            'password': password,
                            'login_url': login_url,
                            'body_preview': body[:200],
                        },
                        'confidence': 'high',
                    })
                    break

    return findings


def test_username_enumeration(
    injector: Any,
    session: Any,
    login_url: str,
    username_field: str = 'email',
    password_field: str = 'password',
) -> List[Dict]:
    """Test if login endpoint reveals whether a username/email exists.

    Sends login requests with different usernames (same wrong password)
    and compares error responses.
    """
    findings = []

    test_usernames = [
        'nonexistent-user-xyz123abc@test.com',
        'admin@test.com',
        'admin@juice-shop.com',
        '0192837465@juice-shop.com',
    ]

    responses = []
    for username in test_usernames:
        payload = {username_field: username, password_field: 'wrongpassword123'}
        resp = injector.inject_post_json(login_url, payload, username_field, 'wrongpassword123')
        responses.append({
            'username': username,
            'status': resp.get('status_code'),
            'body': resp.get('body', ''),
            'ok': resp.get('ok', False),
        })

    # Analyze response differences
    error_msgs = []
    for r in responses:
        body = r['body']
        try:
            data = json.loads(body)
            msg = data.get('errors', data.get('message', data.get('error', '')))
            if msg:
                if isinstance(msg, list):
                    msg = '; '.join(str(m) for m in msg)
                error_msgs.append((r['username'], str(msg)[:100]))
        except json.JSONDecodeError:
            body_lower = body.lower()
            if 'not found' in body_lower or 'does not exist' in body_lower or 'no account' in body_lower:
                error_msgs.append((r['username'], 'user not found'))
            elif 'incorrect' in body_lower or 'invalid' in body_lower or 'wrong' in body_lower:
                error_msgs.append((r['username'], 'invalid credentials'))
            elif r['status'] == 401:
                error_msgs.append((r['username'], 'HTTP 401'))
            elif r['status'] == 403:
                error_msgs.append((r['username'], 'HTTP 403'))

    # Check if different usernames produce different error messages
    unique_msgs = set(msg for _, msg in error_msgs)
    if len(unique_msgs) > 1:
        findings.append({
            'vulnerability': 'Broken Authentication',
            'subtype': 'Username enumeration via login error messages',
            'evidence': {
                'test_results': error_msgs,
                'unique_messages': list(unique_msgs),
            },
            'confidence': 'medium',
        })

    # Also check status code differences
    statuses = set(r['status'] for r in responses)
    if len(statuses) > 1:
        findings.append({
            'vulnerability': 'Broken Authentication',
            'subtype': 'Login returns different HTTP status for existing vs non-existing users',
            'evidence': {
                'test_results': [(r['username'], r['status']) for r in responses],
            },
            'confidence': 'medium',
        })

    return findings


def test_unauthenticated_access(
    injector: Any,
    session: Any,
    base_url: str,
    protected_endpoints: Optional[List[Dict[str, str]]] = None,
) -> List[Dict]:
    """Test if endpoints that should require authentication work without it.

    Temporarily removes auth cookies and tries the endpoints.
    """
    findings = []

    if protected_endpoints is None:
        protected_endpoints = [
            {'url': '/rest/user', 'method': 'GET', 'description': 'User profile'},
            {'url': '/rest/user/wallet', 'method': 'GET', 'description': 'User wallet'},
            {'url': '/rest/address', 'method': 'GET', 'description': 'User address'},
            {'url': '/rest/basket/1', 'method': 'GET', 'description': 'Basket access'},
            {'url': '/rest/order', 'method': 'GET', 'description': 'Orders list'},
        ]

    # Save current cookies
    original_cookies = dict(session.cookies)

    # Remove auth cookies
    auth_cookie_names = [k for k in original_cookies if
                         any(term in k.lower() for term in
                             ['session', 'auth', 'token', 'jwt', 'oidc', 'connect', 'login', 'administrate'])]
    for name in auth_cookie_names:
        session.cookies.pop(name, None)

    session.set_auth_state('anonymous')
    injector.refresh()

    for ep in protected_endpoints:
        url = base_url.rstrip('/') + ep['url']
        method = ep.get('method', 'GET')

        if method == "GET":
            resp = injector.inject_get_raw(url, "")
        elif method == "POST":
            resp = injector._send_request('POST', url, data={})
        elif method == "DELETE":
            resp = injector._send_request('DELETE', url, data={})
        else:
            resp = injector.inject_get_raw(url, "")

        status = resp.get('status_code', 0)
        body = resp.get('body', '')

        # If we got data without auth → missing access control
        if status == 200 and resp.get('ok') and len(body) > 20:
            if not any(x in body.lower() for x in ['login', 'sign in', 'signin', 'authenticate', '404', 'not found']):
                findings.append({
                    'vulnerability': 'Broken Access Control',
                    'subtype': 'Missing authentication — endpoint accessible without login',
                    'endpoint': ep['url'],
                    'method': method,
                    'description': ep.get('description', ''),
                    'evidence': {
                        'status_code': status,
                        'response_length': len(body),
                        'body_preview': body[:300],
                    },
                    'confidence': 'high',
                })

    # Restore cookies
    session.cookies = original_cookies
    session.set_auth_state('authenticated')
    injector.refresh()

    return findings


# ---------------------------------------------------------------------------
# Privilege escalation
# ---------------------------------------------------------------------------

ADMIN_ENDPOINT_PATTERNS = [
    '/admin',
    '/api/admin',
    '/rest/admin',
    '/manage',
    '/dashboard',
    '/users',
    '/users/list',
    '/users/admin',
    '/settings',
    '/config',
    '/logs',
    '/metrics',
    '/console',
    '/phpinfo',
    '/debug',
]


def test_privilege_escalation(
    injector: Any,
    session: Any,
    base_url: str,
    discovered_endpoints: Optional[List[Dict]] = None,
    max_patterns: int = 5,
) -> List[Dict]:
    """Test if a regular user can access admin/privileged endpoints."""
    findings = []

    # Test known admin endpoint patterns
    for pattern in ADMIN_ENDPOINT_PATTERNS[:max(1, max_patterns)]:
        for method in ['GET', 'POST']:
            url = base_url.rstrip('/') + pattern
            if method == 'GET':
                resp = injector.inject_get_raw(url, '')
            else:
                resp = injector._send_request('POST', url, data={})

            status = resp.get('status_code', 0)
            body = resp.get('body', '')

            if status == 200 and resp.get('ok') and len(body) > 50:
                # Skip SPA shells — they return 200 for any route but need auth
                body_lower = body.lower()
                spa_indicators = ['<html', '<head', '<body', 'angular', 'react', 'vue',
                                   ' Appreciation ', ' OWASP ', ' Juice Shop ',
                                   '<!doctype']
                is_spa_shell = any(ind.lower() in body_lower for ind in spa_indicators)
                if is_spa_shell:
                    continue
                if any(x in body_lower for x in ['login', 'sign in', 'signin', 'authenticate', '404 page', 'not found']):
                    continue
                findings.append({
                        'vulnerability': 'Broken Access Control',
                        'subtype': 'Possible privilege escalation — endpoint accessible',
                        'endpoint': url,
                        'method': method,
                        'evidence': {
                            'status_code': status,
                            'response_length': len(body),
                            'body_preview': body[:200],
                        },
                        'confidence': 'medium',
                    })

    # Test discovered endpoints that look admin-related
    if discovered_endpoints:
        for ep in discovered_endpoints:
            url = ep.url if hasattr(ep, 'url') else ep.get('url', '')
            if not url:
                continue
            url_lower = url.lower()
            if any(term in url_lower for term in
                   ['admin', 'manage', 'dashboard', 'config', 'settings',
                    'users', 'logs', 'metrics', 'console', 'debug']):
                resp = injector.inject_get_raw(url, '')
                status = resp.get('status_code', 0)
                if status == 200 and resp.get('ok'):
                    findings.append({
                        'vulnerability': 'Broken Access Control',
                        'subtype': 'Discovered admin-related endpoint accessible',
                        'endpoint': url,
                        'evidence': {'status_code': status},
                        'confidence': 'medium',
                    })

    return findings


# ---------------------------------------------------------------------------
# Session / cookie analysis
# ---------------------------------------------------------------------------

def analyze_cookies(cookies: Dict[str, str]) -> List[Dict]:
    """Analyze cookies for security concerns.

    Note: Full analysis requires Set-Cookie headers to check Secure, HttpOnly,
    SameSite attributes. This is a basic check on cookie names/values.
    """
    findings = []

    for name, val in cookies.items():
        name_lower = name.lower()

        # Sensitive data in cookie name
        sensitive_names = ['password', 'secret', 'key', 'credit', 'ssn']
        for indicator in sensitive_names:
            if indicator in name_lower and len(val) > 0:
                findings.append({
                    'vulnerability': 'Sensitive Data Exposure',
                    'subtype': f'Cookie "{name}" may contain sensitive data',
                    'evidence': {'cookie_name': name, 'value_length': len(val)},
                    'confidence': 'low',
                })

    # Check for plaintext session IDs (heuristic: long random string)
    for name, val in cookies.items():
        if len(val) > 20 and re.match(r'^[A-Za-z0-9_-]+$', val):
            # Could be a session token — flag for manual review
            pass  # Not a finding by itself, but worth noting

    return findings


# ---------------------------------------------------------------------------
# Consolidated access control test runner
# ---------------------------------------------------------------------------

def run_access_control_tests(
    injector: Any,
    session: Any,
    base_url: str,
    login_url: str = '/rest/user/login',
    jwt_token: Optional[str] = None,
    own_email: Optional[str] = None,
    discovered_endpoints: Optional[List[Dict]] = None,
    max_idor_ids: int = 3,
    max_weak_creds: int = 5,
    max_privilege_patterns: int = 5,
    skip_idor: bool = False,
    skip_weak_creds: bool = False,
    skip_enum: bool = False,
    skip_unauth: bool = False,
    skip_priv_esc: bool = True,   # skip by default — too many HTTP calls
) -> List[Dict]:
    """Run all access control and authentication tests.

    Returns a list of findings.
    """
    findings = []

    # 1. JWT analysis
    if jwt_token:
        jwt_findings = analyze_jwt(jwt_token)
        findings.extend(jwt_findings)
        # Extract user info for IDOR testing
        if jwt_token:
            payload = decode_jwt_payload(jwt_token)
            if payload:
                own_email = own_email or payload.get('email') or (payload.get('emails') or [None])[0]
                own_user_id = own_user_id or payload.get('sub') or payload.get('id') or payload.get('userid')

    # 2. IDOR testing
    if not skip_idor:
        idor_findings = test_idor(injector, session, base_url, own_email=own_email, own_user_id=own_user_id)
        findings.extend(idor_findings)

    # 3. Weak credentials (if not already logged in with known creds)
    if not skip_weak_creds:
        if session.auth_state == 'authenticated':
            weak_findings = test_weak_credentials(injector, session, login_url, max_attempts=max_weak_creds)
            findings.extend(weak_findings)

    # 4. Username enumeration
    if not skip_enum:
        enum_findings = test_username_enumeration(injector, session, login_url)
        findings.extend(enum_findings)

    # 5. Unauthenticated access
    if not skip_unauth:
        ua_findings = test_unauthenticated_access(injector, session, base_url)
        findings.extend(ua_findings)

    # 6. Privilege escalation
    if not skip_priv_esc:
        pe_findings = test_privilege_escalation(injector, session, base_url, discovered_endpoints, max_patterns=1)
        findings.extend(pe_findings)

    # 7. Cookie analysis
    cookie_findings = analyze_cookies(session.cookies)
    findings.extend(cookie_findings)

    return findings
