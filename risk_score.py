def calculate_risk(
    detected_threats,
    suspicious_urls,
    sender="",
    subject=""
):
    """
    Calculate risk score based on detected threats and suspicious elements.
    Returns a score from 0-100.
    """
    score = 0
    
    # Base scores for different threat categories
    threat_weights = {
        "Social Engineering": 10,
        "Domain Spoofing": 15,
        "Typosquatting": 15,
        "URL Obfuscation": 15,
        "URL Shortening": 10,
        "Attachment Weaponization": 30,
        "Macro Exploitation": 35,
        "HTML Smuggling": 20,
        "Credential Harvesting": 40,
        "Link Redirection": 15,
        "Impersonation": 20,
        "Scare Tactics": 15,
        "Urgency Manipulation": 15,
        "Fake Branding": 10,
        "QR Code Phishing": 15,
        "Hidden Unicode": 10,
        "Homograph Attack": 20,
        "OAuth Consent": 30,
        "Session Cookie": 35,
        "ZIP Password": 15,
        "Double Extensions": 30,
        "MIME Manipulation": 20,
        "Embedded JavaScript": 20,
        "Reply Chain Hijacking": 10,
        "Malware Payload": 40,
        "Command and Control": 35,
        "Evasion Techniques": 20,
        "AI-Generated": 10,
        "Deepfake": 25,
        "Exploit Delivery": 40,
        "Phishing": 30,
        "Spam": 10,
        "Malware Attachments": 40,
        "Malicious Attachments": 10,
        "Malicious Links": 30,
        "VirusTotal Malicious URL": 45,
        "Email Spoofing": 25,
        "Business Email Compromise": 35,
        "Spear Phishing": 25,
        "Ransomware": 45,
        "Credential Theft": 40,
        "Email Account Takeover": 35,
        "Invoice and Payment Fraud": 35,
        "Password-reset Scams": 30,
        "Email Bombing": 25,
        "OAuth Consent Phishing": 35,
        "Spyware and Keyloggers": 40,
        "Data Leakage": 30,
        "Mailbox-rule Abuse": 35
    }
    
    # Calculate score based on detected threats
    for category in detected_threats.keys():
        if category in threat_weights:
            score += threat_weights[category]
    
    # Additional score for suspicious URLs
    score += len(suspicious_urls) * 8
    
    # Moderate increase for multiple categories
    threat_count = len(detected_threats)
    if threat_count > 1:
        score += max(0, (threat_count - 1) * 4)
    
    # Add bonus for high-risk combinations
    high_risk_combos = [
        ("Credential Harvesting", "Domain Spoofing"),
        ("Malware Payload", "Attachment Weaponization"),
        ("Session Cookie", "OAuth Consent"),
        ("Exploit Delivery", "Evasion Techniques")
    ]
    
    for combo in high_risk_combos:
        if all(cat in detected_threats for cat in combo):
            score += 10
    
    # Normalize and cap at 100
    if score > 100:
        score = 100
    return int(score)