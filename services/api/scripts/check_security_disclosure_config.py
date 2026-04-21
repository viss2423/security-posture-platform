"""Validate security disclosure contact and policy configuration."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any
from urllib.parse import urlparse

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PLACEHOLDER_DOMAINS = (".local", ".invalid", "example.com", "example.org", "example.net")
PLACEHOLDER_VALUES = {
    "security@secplat.local",
    "https://secplat.local/security",
    "http://secplat.local/security",
}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}


def _is_placeholder(value: str) -> bool:
    lowered = str(value or "").strip().lower()
    if not lowered:
        return True
    if lowered in PLACEHOLDER_VALUES:
        return True
    return any(token in lowered for token in PLACEHOLDER_DOMAINS)


def _is_secure_url(value: str) -> bool:
    parsed = urlparse(str(value or "").strip())
    if parsed.scheme == "https":
        return True
    hostname = (parsed.hostname or "").lower()
    return parsed.scheme == "http" and hostname in LOCAL_HOSTS


def evaluate_security_disclosure(
    *,
    contact_email: str,
    contact_url: str,
    policy_url: str,
    require_real: bool,
) -> dict[str, Any]:
    email = str(contact_email or "").strip()
    url = str(contact_url or "").strip()
    policy = str(policy_url or "").strip()
    checks = [
        {
            "check": "security_contact_email_present",
            "ok": bool(email),
            "detail": email or "missing SECURITY_CONTACT_EMAIL",
        },
        {
            "check": "security_contact_email_format",
            "ok": bool(EMAIL_RE.match(email)),
            "detail": "valid email" if EMAIL_RE.match(email) else "invalid contact email",
        },
        {
            "check": "security_policy_url_present",
            "ok": bool(policy),
            "detail": policy or "missing SECURITY_POLICY_URL",
        },
        {
            "check": "security_policy_url_secure",
            "ok": bool(policy) and _is_secure_url(policy),
            "detail": "secure policy url"
            if policy and _is_secure_url(policy)
            else "policy url must use https",
        },
    ]
    if url:
        checks.append(
            {
                "check": "security_contact_url_secure",
                "ok": _is_secure_url(url),
                "detail": "secure contact url"
                if _is_secure_url(url)
                else "contact url must use https",
            }
        )
    if require_real:
        checks.extend(
            [
                {
                    "check": "security_contact_email_real",
                    "ok": not _is_placeholder(email),
                    "detail": "contact email configured"
                    if not _is_placeholder(email)
                    else "contact email is placeholder",
                },
                {
                    "check": "security_policy_url_real",
                    "ok": not _is_placeholder(policy),
                    "detail": "policy url configured"
                    if not _is_placeholder(policy)
                    else "policy url is placeholder",
                },
            ]
        )
        if url:
            checks.append(
                {
                    "check": "security_contact_url_real",
                    "ok": not _is_placeholder(url),
                    "detail": "contact url configured"
                    if not _is_placeholder(url)
                    else "contact url is placeholder",
                }
            )
    errors = [item["detail"] for item in checks if not item["ok"]]
    return {
        "ok": len(errors) == 0,
        "require_real": bool(require_real),
        "checks": checks,
        "errors": errors,
        "contact_email": email,
        "contact_url": url,
        "policy_url": policy,
    }


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contact-email", default=os.getenv("SECURITY_CONTACT_EMAIL", ""))
    parser.add_argument("--contact-url", default=os.getenv("SECURITY_CONTACT_URL", ""))
    parser.add_argument("--policy-url", default=os.getenv("SECURITY_POLICY_URL", ""))
    parser.add_argument(
        "--require-real",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Fail when placeholder contact/policy values are still configured.",
    )
    parser.add_argument("--report-out", default="", help="Optional JSON report output path.")
    args = parser.parse_args(argv)

    out = evaluate_security_disclosure(
        contact_email=args.contact_email,
        contact_url=args.contact_url,
        policy_url=args.policy_url,
        require_real=bool(args.require_real),
    )
    rendered = json.dumps(out, indent=2, sort_keys=True)
    print(rendered)
    if args.report_out:
        with open(args.report_out, "w", encoding="utf-8") as handle:
            handle.write(rendered + "\n")
    return 0 if out["ok"] else 2


if __name__ == "__main__":
    sys.exit(run())
