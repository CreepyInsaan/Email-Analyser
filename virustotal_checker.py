import requests
import base64

API_KEY = "768ce7e28ec4b3a18ecc3b714c80e5ff1f169079901700885252d2e45a73a0df"

def check_url(url):

    encoded_url = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")

    headers = {
        "x-apikey": API_KEY
    }

    vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"

    response = requests.get(
        vt_url,
        headers=headers
    )

    if response.status_code == 200:

        data = response.json()

        malicious = data["data"]["attributes"][
            "last_analysis_stats"
        ]["malicious"]

        return malicious

    return 0