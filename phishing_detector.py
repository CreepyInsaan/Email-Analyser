import re
from email.utils import parseaddr

import tldextract

# Comprehensive phishing detection patterns
PHISHING_PATTERNS = {
    "Social Engineering": [
        r"verify.*account", r"urgent.*action", r"immediate.*response",
        r"account.*suspended", r"security.*alert", r"password.*reset",
        r"login.*required", r"confirm.*identity", r"update.*information",
        r"\bpretend to be\b", r"\bdo not tell anyone\b",
        r"\bkeep this (?:request|transaction) confidential\b",
        r"\bact now or lose\b"
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
    ],
    "Phishing": [
        r"\bverify (?:your )?(?:account|identity|email)\b",
        r"\bconfirm (?:your )?(?:account|identity|details)\b",
        r"\b(?:sign in|log in) to (?:avoid|prevent|restore|continue)\b"
    ],
    "Spam": [
        r"\bbulk email\b", r"\bmass mailing\b",
        r"\bclaim your (?:prize|reward|gift)\b",
        r"\bwork from home.{0,30}(?:earn|income|money)\b",
        r"\byou(?:'ve| have) won.{0,30}(?:prize|cash|gift)\b"
    ],
    "Malicious Links": [
        r"https?://(?:\d{1,3}\.){3}\d{1,3}(?=[:/])",
        r"https?://[^\s/]+/[^?\s]*(?:login|verify|password|credential)[^?\s]*",
        r"https?://[^\s?]+\?(?:url|redirect|return_url|continue)="
    ],
    "Business Email Compromise": [
        r"\b(?:wire|transfer|send|pay) (?:the )?(?:funds|money|payment)\b",
        r"\b(?:urgent|confidential) (?:payment|wire|transfer)\b",
        r"\b(?:gift cards?|bank details|direct deposit)\b"
    ],
    "Spear Phishing": [
        r"\b(?:exclusively|specifically) for you\b",
        r"\bprivate and confidential\b",
        r"\b(?:your project|our conversation|the meeting) yesterday\b"
    ],
    "Ransomware": [
        r"\bfiles? (?:have been|are) encrypted\b",
        r"\bdecrypt(?:ion)? key\b", r"\bransom(?:ware)? payment\b",
        r"\bpay (?:the )?ransom\b"
    ],
    "Credential Theft": [
        r"\b(?:send|share|reply with) (?:your )?(?:password|passcode|one[- ]time code)\b",
        r"\b(?:email|account) password\b.{0,30}\b(?:reply|send|provide)\b",
        r"\b(?:authentication|security) token\b.{0,30}\b(?:share|send|provide)\b"
    ],
    "Email Account Takeover": [
        r"\b(?:unrecognized|unknown|new) sign[- ]in\b",
        r"\bmailbox (?:has been )?(?:compromised|accessed)\b",
        r"\b(?:email|mailbox) account takeover\b",
        r"\bpassword changed without your permission\b"
    ],
    "Invoice and Payment Fraud": [
        r"\b(?:fake|overdue|attached) invoice\b",
        r"\bchange (?:our )?(?:bank|payment|wire) details\b",
        r"\bnew bank account for (?:the )?payment\b",
        r"\bpayment (?:is )?past due\b"
    ],
    "Password-reset Scams": [
        r"\b(?:unexpected|unsolicited) password reset\b",
        r"\breset your password (?:now|immediately|within)\b",
        r"\bpassword reset request.{0,30}(?:not you|did not|wasn't you)\b"
    ],
    "Email Bombing": [
        r"\b(?:email|mailbox|inbox) (?:bombing|flood|flooded)\b",
        r"\binbox (?:was )?flooded with (?:emails|messages)\b",
        r"\bdenial[- ]of[- ]service (?:email|mailbox)\b"
    ],
    "OAuth Consent Phishing": [
        r"\bgrant (?:this|the) app access\b",
        r"\b(?:review|accept) (?:this )?app permissions\b",
        r"\b(?:oauth|application) consent (?:required|request)\b",
        r"\ballow this application to access your (?:mail|email|account)\b"
    ],
    "Spyware and Keyloggers": [
        r"\bkeylogger\b", r"\bkeystrokes? (?:recorded|captured|logged)\b",
        r"\bspyware\b", r"\bmonitoring software\b"
    ],
    "Data Leakage": [
        r"\b(?:confidential|sensitive|personal) data attached\b",
        r"\b(?:social security|ssn|credit card|bank account) number\b",
        r"\bapi[_ -]?key\s*[:=]\s*[a-z0-9_-]{8,}\b",
        r"\bpassword\s*[:=]\s*\S{6,}\b"
    ],
    "Mailbox-rule Abuse": [
        r"\b(?:mailbox|inbox) forwarding rule\b",
        r"\bforward (?:all|every) (?:your )?(?:email|message)s? to\b",
        r"\b(?:inbox|mailbox) rule (?:created|changed|added)\b",
        r"\bhide (?:these|the) (?:email|message)s? from\b"
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


def detect_phishing(text, sender="", subject="", urls=None, attachments=None):
    """
    Comprehensive phishing detection function.
    Returns a dictionary with detected threats categorized by type.
    """
    if urls is None:
        urls = []
    if attachments is None:
        attachments = []
        
    text_lower = f"{subject} {text}".lower()
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

    # Attachment names are available in Gmail metadata even when file contents
    # are not downloaded. Flag risky extensions, but do not claim file scanning.
    risky_extensions = (
        ".exe", ".scr", ".pif", ".bat", ".cmd", ".com", ".vbs", ".vbe",
        ".js", ".jse", ".jar", ".hta", ".wsf", ".ps1", ".iso", ".img",
        ".lnk", ".reg", ".chm", ".one", ".docm", ".xlsm", ".pptm", ".html"
    )
    suspicious_attachment_extensions = (
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".rar", ".7z"
    )
    for filename in attachments:
        filename_lower = filename.lower()
        if filename_lower.endswith(risky_extensions):
            detected_threats.setdefault("Malware Attachments", []).append(filename)
            if re.search(r"\.(?:pdf|docx?|xlsx?|jpe?g|png)\.(?:exe|scr|js|vbs|bat)$", filename_lower):
                detected_threats.setdefault("Double Extensions", []).append(filename)
        elif filename_lower.endswith(suspicious_attachment_extensions):
            detected_threats.setdefault("Malicious Attachments", []).append(filename)

    # Look for high-risk URLs in the URL field as well as the message text.
    for url in urls:
        url_lower = url.lower()
        url_suffix = tldextract.extract(url).suffix
        if (
            any(re.search(pattern, url_lower, re.IGNORECASE)
                for pattern in PHISHING_PATTERNS["Malicious Links"])
            or f".{url_suffix}" in SUSPICIOUS_TLDS
        ):
            detected_threats.setdefault("Malicious Links", []).append(url)
    
    # Additional domain-specific checks
    display_name, sender_address = parseaddr(sender)
    sender_domain = sender_address.rsplit("@", 1)[-1].lower()
    extracted_sender_domain = tldextract.extract(sender_domain).domain
    trusted_brands = ["google", "microsoft", "apple", "amazon", "facebook", "linkedin", "paypal"]
    if any(
        brand in display_name.lower() and extracted_sender_domain != brand
        for brand in trusted_brands
    ):
        detected_threats.setdefault("Email Spoofing", []).append(
            f"Trusted brand display name does not match sender domain: {sender_domain}"
        )

    suspicious_domain_reason = is_suspicious_sender_domain(sender_lower)
    if suspicious_domain_reason:
        if "Domain Spoofing" not in detected_threats:
            detected_threats["Domain Spoofing"] = []
        detected_threats["Domain Spoofing"].append(suspicious_domain_reason)
    
    # Check for typosquatting in domain
    extracted = tldextract.extract(sender_lower)
    common_domains = trusted_brands
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
        elif category == "Phishing":
            summary.append("Phishing indicators detected")
        elif category == "Spam":
            summary.append("Spam or bulk-mail indicators detected")
        elif category in ("Malware Attachments", "Malicious Attachments"):
            summary.append("Potentially risky attachment type detected; file contents not scanned")
        elif category == "Email Spoofing":
            summary.append("Sender display name does not match its apparent domain")
        elif category == "Malicious Links":
            summary.append("Potentially malicious link indicators")
        elif category == "VirusTotal Malicious URL":
            summary.append("VirusTotal reports malicious URL reputation")
        elif category == "Business Email Compromise":
            summary.append("Business email compromise indicators")
        elif category == "Spear Phishing":
            summary.append("Targeted phishing indicators")
        elif category == "Ransomware":
            summary.append("Ransomware indicators detected")
        elif category == "Credential Theft":
            summary.append("Credential theft indicators")
        elif category == "Email Account Takeover":
            summary.append("Email account takeover indicators")
        elif category == "Invoice and Payment Fraud":
            summary.append("Invoice or payment fraud indicators")
        elif category == "Password-reset Scams":
            summary.append("Password-reset scam indicators")
        elif category == "Email Bombing":
            summary.append("Email bombing or mailbox flooding indicators")
        elif category == "OAuth Consent Phishing":
            summary.append("OAuth consent phishing indicators")
        elif category == "Spyware and Keyloggers":
            summary.append("Spyware or keylogger indicators")
        elif category == "Data Leakage":
            summary.append("Potential sensitive data disclosure")
        elif category == "Mailbox-rule Abuse":
            summary.append("Mailbox rule abuse indicators")
    
    return summary