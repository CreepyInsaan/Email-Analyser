import ipaddress
import re
from urllib.parse import urlsplit

import tldextract


bad_tlds = {
    "xyz", "ru", "tk", "top", "cn", "in", "info", "biz", "online",
    "site", "club", "pro", "cc", "ws", "ga", "ml", "cf", "gq",
    "work", "click", "link", "download", "stream", "review", "party",
    "trade", "science", "loan", "win", "bid", "date", "faith",
    "racing", "webcam", "men", "zip", "accountant", "cricket",
}

_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_TRAILING_PUNCTUATION = ".,;:!?)]}"


def extract_urls(text):
    """Extract unique HTTP(S) URLs, trimming punctuation around email links."""
    urls = []
    seen = set()

    for match in _URL_PATTERN.findall(text):
        url = match.rstrip(_TRAILING_PUNCTUATION)
        if url and url not in seen:
            seen.add(url)
            urls.append(url)

    return urls


def analyze_urls(urls):
    """Return unique URLs with a suspicious host or URL structure."""
    suspicious = []
    seen = set()

    for url in urls:
        try:
            parsed = urlsplit(url)
            hostname = parsed.hostname
        except ValueError:
            hostname = None
            parsed = None

        if not parsed or not hostname:
            continue

        hostname = hostname.lower().rstrip(".")
        reasons = []
        try:
            ipaddress.ip_address(hostname)
            reasons.append("IP-address host")
        except ValueError:
            extracted = tldextract.extract(hostname)
            if extracted.suffix.lower() in bad_tlds:
                reasons.append(f"Suspicious TLD: .{extracted.suffix}")

        if parsed.username is not None:
            reasons.append("Embedded URL credentials")
        if hostname.startswith("xn--") or ".xn--" in hostname:
            reasons.append("Punycode hostname")

        if reasons and url not in seen:
            seen.add(url)
            suspicious.append(url)

    return suspicious
