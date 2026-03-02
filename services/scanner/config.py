"""Scanner config: scope (internal_only | internal_and_verified), API, internal URLs, interval."""
import os

SCOPE = os.environ.get("SCANNER_SCOPE", "internal_only")  # internal_only | internal_and_verified
API_URL = os.environ.get("API_URL", "http://api:8000").rstrip("/")
SCAN_INTERVAL_SECONDS = int(os.environ.get("SCAN_INTERVAL_SECONDS", "21600"))  # 6h default

# Internal lab targets: list of (base_url, asset_key). Used for internal_only and always included for internal_and_verified.
# INTERNAL_TARGETS = "http://verify-web|verify-web,http://juiceshop:3000|juice-shop,http://api:8000|secplat-api"
# Or leave unset to derive from VERIFY_WEB_URL, JUICE_URL, API_URL with default asset_keys.
def _internal_targets() -> list[tuple[str, str]]:
    raw = os.environ.get("INTERNAL_TARGETS", "").strip()
    if raw:
        out = []
        for part in raw.split(","):
            part = part.strip()
            if "|" in part:
                url, key = part.split("|", 1)
                out.append((url.strip(), key.strip()))
            else:
                url = part
                from urllib.parse import urlparse
                p = urlparse(url if url.startswith("http") else "http://" + url)
                key = (p.hostname or "internal").replace(".", "-")
                out.append((url if url.startswith("http") else "http://" + url, key))
        return out
    # Default mapping from common env vars to asset_keys (match ingestion seed)
    targets = []
    for var, default_key in (("VERIFY_WEB_URL", "verify-web"), ("JUICE_URL", "juice-shop"), ("API_URL", "secplat-api")):
        val = os.environ.get(var, "").strip()
        if not val:
            continue
        if not val.startswith("http"):
            val = "http://" + val
        try:
            from urllib.parse import urlparse
            p = urlparse(val)
            base = f"{p.scheme}://{p.netloc}"
            if not any(b == base for b, _ in targets):
                targets.append((base, default_key))
        except Exception:
            targets.append((val, default_key))
    return targets

INTERNAL_TARGETS = _internal_targets()  # list of (url, asset_key)

# Timeouts and safety
REQUEST_TIMEOUT = float(os.environ.get("SCANNER_REQUEST_TIMEOUT", "15.0"))
MAX_TARGETS = int(os.environ.get("SCANNER_MAX_TARGETS", "50"))  # cap for verified external
