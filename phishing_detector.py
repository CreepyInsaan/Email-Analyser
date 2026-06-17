import re
import tldextract

# Comprehensive phishing detection patterns
PHISHING_PATTERNS = {
    "Social Engineering": [
        r"verify.*account", r"urgent.*action", r"immediate.*response",
        r"account.*suspended", r"security.*alert", r"password.*reset",
        r"login.*required", r"confirm.*identity", r"update.*information"
    ],
    "Domain Spoofing": [
        r"@.*-.*\..*",   # Hyphens in suspicious places
    ],
    "Typosquatting": [
        r"linkedln", r"g00gle", r"paypa1", r"amaz0n", r"micr0soft",
        r"faceb00k", r"instagrarn", r"twiter", r"netfl1x"
    ],
    "URL Obfuscation": [
        r"%[0-9A-F]{2}",  # URL encoding
        r"\\x[0-9A-F]{2}",  # Hex encoding
        r"javascript:", r"data:", r"vbscript:"
    ],
    "URL Shortening": [
        r"bit\.ly", r"tinyurl\.com", r"t\.co", r"goo\.gl",
        r"ow\.ly", r"is\.gd", r"buff\.ly", r"adf\.ly"
    ],
    "Attachment Weaponization": [
        r"\.exe\b", r"\.scr\b", r"\.pif\b", r"\.bat\b", r"\.cmd\b",
        r"\.vbs\b", r"\.js\b", r"\.jar\b", r"\.hta\b", r"\.wsf\b"
    ],
    "Macro Exploitation": [
        r"enable.*macro", r"macro.*enabled", r"run.*macro",
        r"document.*macro", r"spreadsheet.*macro"
    ],
    "HTML Smuggling": [
        r"<script", r"javascript:", r"onload=", r"onerror=",
        r"document\.write", r"eval\("
    ],
    "Credential Harvesting": [
        r"enter.*password", r"login.*credentials", r"username.*password",
        r"account.*details", r"authentication.*required"
    ],
    "Link Redirection": [
        r"redirect", r"redirected", r"click.*here", r"follow.*link"
    ],
    "Impersonation": [
        r"ceo", r"boss", r"manager", r"hr.*department", r"it.*support",
        r"bank.*manager", r"legal.*department"
    ],
    "Scare Tactics": [
        r"account.*blocked", r"access.*denied", r"security.*breach",
        r"virus.*detected", r"compromised", r"hacked"
    ],
    "Urgency Manipulation": [
        r"within.*24.*hours", r"immediately", r"urgent", r"asap",
        r"time.*sensitive", r"deadline", r"expires.*soon"
    ],
    "Fake Branding": [
        r"official.*logo", r"company.*branding", r"trusted.*sender"
    ],
    "QR Code Phishing": [
        r"qr.*code", r"scan.*qr", r"mobile.*app", r"camera.*scan"
    ],
    "Hidden Unicode": [
        r"\u00A0", r"\u200B", r"\u200C", r"\u200D", r"\uFEFF"  # Various invisible chars
    ],
    "Homograph Attack": [
        r"rnicrosoft", r"gοogle", r"аррӏе", r"fаcebook"  # Unicode lookalikes
    ],
    "OAuth Consent": [
        r"grant.*permission", r"authorize.*access", r"consent.*required",
        r"oauth", r"api.*access"
    ],
    "Session Cookie": [
        r"cookie", r"session.*id", r"auth.*token", r"bearer.*token"
    ],
    "ZIP Password": [
        r"password.*protected", r"zip.*password", r"extract.*password"
    ],
    "Double Extensions": [
        r"\.pdf\.exe", r"\.doc\.exe", r"\.jpg\.exe", r"\.txt\.vbs"
    ],
    "MIME Manipulation": [
        r"content-type", r"mime.*type", r"attachment.*type"
    ],
    "Embedded JavaScript": [
        r"<script>", r"javascript:", r"onclick=", r"onmouseover="
    ],
    "Reply Chain Hijacking": [
        r"re:", r"fw:", r"reply.*all", r"thread.*hijack"
    ],
    "Malware Payload": [
        r"payload", r"malware", r"trojan", r"ransomware", r"spyware"
    ],
    "Command and Control": [
        r"c2", r"command.*control", r"botnet", r"remote.*access"
    ],
    "Evasion Techniques": [
        r"bypass", r"evade", r"stealth", r"obfuscate", r"encrypt"
    ],
    "AI-Generated": [
        r"ai.*generated", r"artificial.*intelligence", r"machine.*learning"
    ],
    "Deepfake": [
        r"deepfake", r"voice.*clone", r"video.*call", r"meeting.*link"
    ],
    "Exploit Delivery": [
        r"exploit", r"vulnerability", r"zero.*day", r"patch.*required"
    ]
}

SUSPICIOUS_TLDS = [
    ".xyz", ".ru", ".tk", ".top", ".cn", ".in", ".info", ".biz",
    ".online", ".site", ".club", ".pro", ".cc", ".ws", ".ga", ".ml",
    ".cf", ".gq", ".work", ".click", ".link", ".download", ".stream",
    ".review", ".party", ".trade", ".science", ".loan", ".win", ".bid",
    ".date", ".faith", ".racing", ".webcam", ".men", ".zip", ".accountant",
    ".cricket", ".loan", ".science", ".trade"
]

def is_suspicious_sender_domain(sender_lower):
    extracted = tldextract.extract(sender_lower)
    if not extracted.suffix:
        return None

    # Suspicious top-level domains only
    if extracted.suffix in SUSPICIOUS_TLDS:
        return f"Suspicious TLD: .{extracted.suffix}"

    suspicious_subdomains = ["login", "secure", "account", "verify", "update", "support", "admin"]
    if extracted.subdomain:
        for keyword in suspicious_subdomains:
            if keyword in extracted.subdomain:
                return f"Suspicious subdomain: {extracted.subdomain}"

    return None


def detect_phishing(text, sender="", subject="", urls=None):
    """
    Comprehensive phishing detection function.
    Returns a dictionary with detected threats categorized by type.
    """
    if urls is None:
        urls = []
        
    text_lower = text.lower()
    sender_lower = sender.lower()
    subject_lower = subject.lower()
    
    detected_threats = {}
    
    # Check each category of threats
    for category, patterns in PHISHING_PATTERNS.items():
        found_in_category = []
        
        for pattern in patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                found_in_category.append(pattern)
        
        if found_in_category:
            detected_threats[category] = found_in_category
    
    # Additional domain-specific checks
    suspicious_domain_reason = is_suspicious_sender_domain(sender_lower)
    if suspicious_domain_reason:
        if "Domain Spoofing" not in detected_threats:
            detected_threats["Domain Spoofing"] = []
        detected_threats["Domain Spoofing"].append(suspicious_domain_reason)
    
    # Check for typosquatting in domain
    extracted = tldextract.extract(sender_lower)
    common_domains = ["google", "microsoft", "apple", "amazon", "facebook", "linkedin", "paypal"]
    for real_domain in common_domains:
        if real_domain in extracted.domain and extracted.domain != real_domain:
            if "Typosquatting" not in detected_threats:
                detected_threats["Typosquatting"] = []
            detected_threats["Typosquatting"].append(f"Possible {real_domain} spoofing")
    
    # Check URLs for obfuscation and shortening
    for url in urls:
        url_lower = url.lower()
        
        # URL shortening services
        for shortener in PHISHING_PATTERNS["URL Shortening"]:
            if shortener.replace(r"\.", ".") in url_lower:
                if "URL Shortening" not in detected_threats:
                    detected_threats["URL Shortening"] = []
                detected_threats["URL Shortening"].append(url)
        
        # URL obfuscation
        if "%" in url or "\\x" in url:
            if "URL Obfuscation" not in detected_threats:
                detected_threats["URL Obfuscation"] = []
            detected_threats["URL Obfuscation"].append(url)
    
    return detected_threats

def get_threat_summary(detected_threats):
    """
    Convert detected threats into a summary list for display.
    """
    summary = []
    
    for category, threats in detected_threats.items():
        if category == "Social Engineering":
            summary.append("Social engineering tactics detected")
        elif category == "Domain Spoofing":
            summary.append("Domain spoofing indicators")
        elif category == "Typosquatting":
            summary.append("Typosquatting domain detected")
        elif category == "URL Obfuscation":
            summary.append("URL obfuscation found")
        elif category == "URL Shortening":
            summary.append("Shortened URLs detected")
        elif category == "Attachment Weaponization":
            summary.append("Potentially malicious attachments")
        elif category == "Macro Exploitation":
            summary.append("Macro exploitation attempt")
        elif category == "HTML Smuggling":
            summary.append("HTML smuggling detected")
        elif category == "Credential Harvesting":
            summary.append("Credential harvesting attempt")
        elif category == "Link Redirection":
            summary.append("Link redirection tactics")
        elif category == "Impersonation":
            summary.append("Impersonation attempt")
        elif category == "Scare Tactics":
            summary.append("Scare tactics used")
        elif category == "Urgency Manipulation":
            summary.append("Urgency manipulation")
        elif category == "Fake Branding":
            summary.append("Fake branding detected")
        elif category == "QR Code Phishing":
            summary.append("QR code phishing (Quishing)")
        elif category == "Hidden Unicode":
            summary.append("Hidden Unicode characters")
        elif category == "Homograph Attack":
            summary.append("Homograph attack detected")
        elif category == "OAuth Consent":
            summary.append("OAuth consent abuse")
        elif category == "Session Cookie":
            summary.append("Session cookie theft attempt")
        elif category == "ZIP Password":
            summary.append("ZIP password protection")
        elif category == "Double Extensions":
            summary.append("Double file extensions")
        elif category == "MIME Manipulation":
            summary.append("MIME type manipulation")
        elif category == "Embedded JavaScript":
            summary.append("Embedded JavaScript")
        elif category == "Reply Chain Hijacking":
            summary.append("Reply chain hijacking")
        elif category == "Malware Payload":
            summary.append("Malware payload staging")
        elif category == "Command and Control":
            summary.append("C2 delivery attempt")
        elif category == "Evasion Techniques":
            summary.append("Evasion techniques used")
        elif category == "AI-Generated":
            summary.append("AI-generated content")
        elif category == "Deepfake":
            summary.append("Deepfake elements")
        elif category == "Exploit Delivery":
            summary.append("Exploit delivery")
    
    return summary