import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from app import threat_intel


def test_extract_candidate_normalizes_domain_and_ip():
    assert (
        threat_intel._extract_candidate(
            "https://Example.COM/login",
            indicator_type="domain",
        )
        == "example.com"
    )
    assert (
        threat_intel._extract_candidate(
            "198.51.100.10,malicious",
            indicator_type="ip",
        )
        == "198.51.100.10"
    )


def test_parse_text_feed_skips_comments_and_invalid_values():
    content = """
    # comment
    bad value here
    203.0.113.20
    https://evil.example/path
    ; another comment
    """

    ip_indicators = threat_intel._parse_text_feed(content, indicator_type="ip")
    domain_indicators = threat_intel._parse_text_feed(content, indicator_type="domain")

    assert ip_indicators == ["203.0.113.20"]
    assert "evil.example" in domain_indicators
