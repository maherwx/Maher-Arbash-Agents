"""Declared response-header and cookie policies; no raw values in evidence."""
import re
from http.cookies import SimpleCookie, CookieError


_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


def validate_response_policy(expected):
    count = 0
    for field, supported in (("response_headers", {"present", "equals", "contains", "comma_tokens"}),
                             ("response_cookies", {"secure", "httponly", "samesite", "path", "domain_absent"})):
        rows = expected.get(field, {})
        if not isinstance(rows, dict) or (field in expected and not rows) or len(rows) > 100:
            raise ValueError("response policies require bounded nonempty mappings")
        for name, policy in rows.items():
            if not isinstance(name, str) or len(name) > 128 or not _TOKEN.fullmatch(name):
                raise ValueError("response policy name must be an HTTP token")
            if not isinstance(policy, dict) or not policy or set(policy) - supported:
                raise ValueError("unsupported response policy assertion")
            for key, value in policy.items():
                if key in {"present", "secure", "httponly", "domain_absent"}:
                    if type(value) is not bool:
                        raise ValueError("response policy flags must be booleans")
                elif key == "samesite":
                    if not isinstance(value, str) or value not in {"Lax", "Strict", "None"}:
                        raise ValueError("cookie SameSite must be Lax, Strict or None")
                elif key == "comma_tokens":
                    if (not isinstance(value, list) or not value or len(value) > 100
                            or any(not isinstance(token, str) or len(token) > 128 or not _TOKEN.fullmatch(token) for token in value)):
                        raise ValueError("comma_tokens requires bounded HTTP tokens")
                elif not isinstance(value, str) or not value or len(value) > 4096 or "\r" in value or "\n" in value:
                    raise ValueError("response policy values must be bounded single-line strings")
                count += 1
            if field == "response_headers" and policy.get("present") is False and len(policy) > 1:
                raise ValueError("absent header cannot also have value assertions")
    return count


def _items(response):
    rows = response.get("header_items")
    # Cookie checks need the duplicate-preserving representation. A collapsed
    # dict cannot establish all Set-Cookie attributes or absence reliably.
    duplicate_preserved = isinstance(rows, list)
    if rows is None and isinstance(response.get("headers"), dict):
        rows = list(response["headers"].items())
    if not isinstance(rows, list) or len(rows) > 1000:
        return {}, False, False
    grouped, size = {}, 0
    for row in rows:
        if not isinstance(row, (list, tuple)) or len(row) != 2:
            return {}, False, False
        name, value = row
        if not isinstance(name, str) or not isinstance(value, str) or not _TOKEN.fullmatch(name):
            return {}, False, False
        size += len(name) + len(value)
        if size > 131072 or "\r" in value or "\n" in value:
            return {}, False, False
        grouped.setdefault(name.lower(), []).append(value)
    return grouped, duplicate_preserved, not response.get("headers_incomplete", False)


def _comma_tokens(values):
    # Parse commas outside quoted directive values. Unbalanced quotes or empty
    # members are ambiguous and cannot provide token evidence.
    tokens = set()
    for value in values:
        quoted, escaped, start = False, False, 0
        parts = []
        for index, char in enumerate(value):
            if escaped:
                escaped = False
            elif quoted and char == "\\":
                escaped = True
            elif char == '"':
                quoted = not quoted
            elif char == "," and not quoted:
                parts.append(value[start:index])
                start = index + 1
        if quoted or escaped:
            return None
        parts.append(value[start:])
        for part in parts:
            member = part.strip()
            token = member.split("=", 1)[0].strip()
            if not _TOKEN.fullmatch(token):
                return None
            if "=" not in member:
                tokens.add(token.lower())
    return tokens


def response_policy_assertions(response, expected):
    if not expected.get("response_headers") and not expected.get("response_cookies"):
        return []
    grouped, duplicate_preserved, complete = _items(response)
    checks = []
    for name, policy in expected.get("response_headers", {}).items():
        values = grouped.get(name.lower(), [])
        for operator, wanted in policy.items():
            passed = False
            evidence_complete = complete and (operator == "present" or duplicate_preserved)
            if complete:
                if operator == "present":
                    passed = bool(values) is wanted
                elif operator == "equals" and duplicate_preserved:
                    passed = len(values) == 1 and values[0] == wanted
                elif operator == "contains" and duplicate_preserved:
                    passed = bool(values) and all(wanted in value for value in values)
                elif operator == "comma_tokens" and duplicate_preserved:
                    tokens = _comma_tokens(values) if values else None
                    # Missing header is a complete policy mismatch; malformed
                    # list syntax is uncertain evidence instead.
                    if values and tokens is None:
                        evidence_complete = False
                    passed = tokens is not None and all(token.lower() in tokens for token in wanted)
            checks.append({"kind": "response_header", "header": name.lower(),
                           "operator": operator, "passed": passed,
                           "evidence_complete": evidence_complete})
    if not expected.get("response_cookies"):
        return checks
    cookies, cookies_valid = {}, complete and duplicate_preserved
    for value in grouped.get("set-cookie", []):
        parsed = SimpleCookie()
        try:
            parsed.load(value)
        except CookieError:
            cookies_valid = False
            continue
        if len(parsed) != 1:
            cookies_valid = False
            continue
        for name, morsel in parsed.items():
            cookies.setdefault(name, []).append(morsel)
    for name, policy in expected.get("response_cookies", {}).items():
        values = cookies.get(name, [])
        for operator, wanted in policy.items():
            passed = False
            evidence_complete = cookies_valid and len(values) <= 1
            # Reissued same-name cookies can differ in path/domain and replace
            # one another. Do not infer a unique effective cookie from them.
            if cookies_valid and len(values) == 1:
                cookie = values[0]
                if operator in {"secure", "httponly"}:
                    passed = bool(cookie[operator]) is wanted
                elif operator == "samesite":
                    passed = cookie["samesite"].lower() == wanted.lower()
                elif operator == "path":
                    passed = cookie["path"] == wanted
                elif operator == "domain_absent":
                    passed = (not bool(cookie["domain"])) is wanted
            checks.append({"kind": "response_cookie", "cookie": name,
                           "operator": operator, "passed": passed,
                           "evidence_complete": evidence_complete})
    return checks
