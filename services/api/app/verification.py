import secrets
import string
import urllib.request
import urllib.error

def generate_token(length: int = 24) -> str:
    # URL-safe-ish token (letters+digits), easy to paste into DNS/HTTP
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))

def _http_get(url: str, timeout: int = 3) -> tuple[bool, str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "secplat-verifier/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
        return True, body
    except urllib.error.HTTPError as e:
        return False, f"HTTPError {e.code}: {e.reason}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"

def verify_domain_ownership(domain: str, token: str, method: str) -> tuple[bool, dict]:
    """
    Methods:
      - dns_txt: expects TXT record containing: secplat-verification=<token>
      - well_known: expects GET http://<domain>/.well-known/secplat-verification.txt
                   response body containing the token (exact match trimmed)
    """
    if not method:
        return False, {"error": "method is required", "allowed": ["dns_txt", "well_known"]}

    method = method.strip().lower()

    # allow optional port in domain (e.g., host.docker.internal:8081)
    host = domain.strip()

    if method == "well_known":
        url = f"http://{host}/.well-known/secplat-verification.txt"
        ok, body = _http_get(url)
        if not ok:
            return False, {"method": "well_known", "url": url, "error": body}

        got = body.strip()
        expected = token.strip()
        if got != expected:
            return False, {
                "method": "well_known",
                "url": url,
                "error": "token mismatch",
                "expected": expected,
                "got": got[:200],
            }

        return True, {"method": "well_known", "url": url}

    if method == "dns_txt":
        # dnspython is the simplest way. If not installed, return a helpful error.
        try:
            import dns.resolver  # type: ignore
        except Exception:
            return False, {
                "method": "dns_txt",
                "error": "dnspython not installed. Add it to dependencies (pip install dnspython).",
                "expected_txt": f"secplat-verification={token}",
            }

        expected = f"secplat-verification={token}"
        try:
            answers = dns.resolver.resolve(host, "TXT")
            records = []
            for rdata in answers:
                # rdata.strings may be bytes pieces; normalize into a full string
                txt = "".join(s.decode() if isinstance(s, (bytes, bytearray)) else str(s) for s in getattr(rdata, "strings", []))
                if not txt:
                    txt = str(rdata).strip('"')
                records.append(txt)

            if any(expected in r for r in records):
                return True, {"method": "dns_txt", "host": host, "matched": expected}

            return False, {"method": "dns_txt", "host": host, "expected_txt": expected, "found": records}
        except Exception as e:
            return False, {"method": "dns_txt", "host": host, "error": f"{type(e).__name__}: {e}"}

    return False, {"error": "invalid method", "allowed": ["dns_txt", "well_known"]}
