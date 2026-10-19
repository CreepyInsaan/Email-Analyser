import base64
import os

import requests


class VirusTotalError(RuntimeError):
    """Raised when VirusTotal cannot provide a URL reputation result."""


def check_url(url):
    """Return VirusTotal's malicious-engine count, or None if the URL is unknown."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise VirusTotalError(
            "VIRUSTOTAL_API_KEY is not set; VirusTotal URL checks are unavailable"
        )

    encoded_url = base64.urlsafe_b64encode(url.encode("utf-8")).decode().rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(endpoint, headers=headers, timeout=15)
    except requests.RequestException as exc:
        raise VirusTotalError("VirusTotal request failed") from exc

    if response.status_code == 404:
        return None

    try:
        response.raise_for_status()
    except requests.RequestException as exc:
        raise VirusTotalError(
            f"VirusTotal returned HTTP {response.status_code}"
        ) from exc

    try:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        malicious_count = stats["malicious"]
    except (ValueError, KeyError, TypeError) as exc:
        raise VirusTotalError("VirusTotal returned an invalid URL analysis response") from exc

    if not isinstance(malicious_count, int) or malicious_count < 0:
        raise VirusTotalError("VirusTotal returned an invalid malicious-engine count")

    return malicious_count
