import re

bad_tlds = [
    ".xyz",
    ".ru",
    ".tk",
    ".top",
    ".cn",
    ".in",
    ".info",
    ".biz",
    ".online",
    ".site",
    ".club",
    ".pro",
    ".cc",
    ".ws",
    ".ga",
    ".ml",
    ".cf",
    ".gq",
    ".work",
    ".click",
    ".link",
    ".download",
    ".stream",
    ".review",
    ".party",
    ".trade",
    ".science",
    ".loan",
    ".win",
    ".bid",
    ".date",
    ".faith",
    ".racing",
    ".webcam",
    ".men",
    ".zip",
    ".accountant",
    ".cricket",
    ".loan",
    ".science",
    ".trade"
]

def extract_urls(text):

    url_pattern = r'https?://[^\s]+'

    return re.findall(url_pattern, text)


def analyze_urls(urls):

    suspicious = []

    for url in urls:

        for tld in bad_tlds:

            if tld in url:
                suspicious.append(url)

    return suspicious