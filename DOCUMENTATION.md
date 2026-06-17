# Gmail Threat Analyzer Documentation

## Project Overview

Gmail Threat Analyzer is a Python-based email security tool that scans Gmail messages for phishing, spoofing, malicious links, and other suspicious indicators. It uses Gmail API access to read inbox messages, applies heuristic rules to detect threats, computes a risk score, logs results to a SIEM file, and avoids re-checking previously analyzed emails.

## Architecture

The project is organized into modular components:

- `gmail_reader.py`: Main workflow. Authenticates with Gmail, fetches messages, extracts email text, runs detection, computes risk, and outputs results.
- `phishing_detector.py`: Detection engine for phishing tactics, suspicious content, spoofing patterns, and URL-based threats.
- `url_checker.py`: URL extraction and suspicious domain analysis.
- `virustotal_checker.py`: VirusTotal URL reputation checks.
- `risk_score.py`: Converts detected threats and suspicious URLs into a normalized risk score.
- `siem_logger.py`: Writes event logs to `logs/siem_logs.json` and loads previous results to prevent duplicate analysis.
- `actions.py`: Placeholder for follow-up actions such as quarantining or moving email messages.

## Files Description

- `README.md`: Project overview and quick start.
- `DOCUMENTATION.md`: In-depth documentation for developers and users.
- `gmail_reader.py`: Entry point for running the live email scan.
- `phishing_detector.py`: Threat detection and summary generation.
- `url_checker.py`: URL extraction and bad-TLD detection.
- `virustotal_checker.py`: Third-party VirusTotal checks.
- `risk_score.py`: Risk calculation logic.
- `siem_logger.py`: SIEM-style logging and duplicate skip support.
- `actions.py`: Email action helpers.
- `credentials.json`: OAuth client credentials (sensitive; not committed).
- `token.json`: Cached Gmail OAuth token.
- `logs/siem_logs.json`: Append-only log file storing scan results.

## Installation

1. Install Python 3.10 or newer.
2. Create and activate a virtual environment:

```bash
python -m venv venv
venv\Scripts\Activate.ps1   # PowerShell
venv\Scripts\activate.bat   # Command Prompt
```

3. Install project dependencies:

```bash
pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib beautifulsoup4 colorama validators tldextract requests
```

4. Create a `requirements.txt` file if desired:

```text
google-api-python-client
google-auth-httplib2
google-auth-oauthlib
beautifulsoup4
colorama
validators
tldextract
requests
```

## Configuration

1. Enable the Gmail API in Google Cloud Console.
2. Create OAuth 2.0 client credentials.
3. Download the credentials file as `credentials.json` and place it in the project root.
4. Run the tool once to generate `token.json`.

### Important security notes

- Keep `credentials.json` and `token.json` private.
- Do not commit these files to version control.
- `virustotal_checker.py` currently includes a hardcoded `API_KEY`; replace this with a secure configuration method such as environment variables.

## Running the Analyzer

Execute the main script:

```bash
python gmail_reader.py
```

The first run will prompt for Gmail OAuth authentication using the browser. Once authenticated, the token is stored in `token.json`.

### What happens during a run

1. Authenticate with Gmail.
2. List messages in the inbox.
3. Retrieve each message and extract headers and body text.
4. Extract URLs from the email text.
5. Analyze URLs for suspicious TLDs.
6. Check URLs with VirusTotal.
7. Detect phishing threats using heuristic patterns.
8. Compute a risk score.
9. Log results to `logs/siem_logs.json`.
10. Display the analysis summary.

## Detection Flow

### Email extraction

- The message body is extracted from Gmail payload parts.
- Plain text is preferred; HTML is stripped of tags if needed.

### Threat detection

`phishing_detector.py` identifies suspicious content using multiple pattern categories such as:

- Social engineering
- Domain spoofing
- Typosquatting
- URL obfuscation
- URL shortening
- Attachment weaponization
- Macro exploitation
- HTML smuggling
- Credential harvesting
- Impersonation and urgency tactics
- Fake branding
- Homograph attacks
- OAuth abuse
- Session cookie theft
- Malware payload delivery
- Command-and-control and evasion techniques

It also looks for suspicious sender domains and common brand spoofing.

### URL analysis

`url_checker.py` extracts URLs and flags those containing risky top-level domains such as `.xyz`, `.ru`, `.tk`, `.top`, `.cn`, and others.

### VirusTotal checks

`virustotal_checker.py` queries VirusTotal for URL reputation and adds malicious counts to the analysis summary.

### Risk scoring

`risk_score.py` assigns weights to detected threat categories and adds points for suspicious URLs. Scores are normalized to a maximum of `100`.

- `70+`: PHISHING
- `40-69`: SUSPICIOUS
- `20-39`: LOW RISK
- `<20`: SAFE

## Logging and SIEM Support

`siem_logger.py` writes one JSON entry per analyzed email to `logs/siem_logs.json`.

Each log entry includes:

- timestamp
- sender
- subject
- risk_score
- threat details
- message_id (when available)

The tool uses these logs to skip repeated analysis for the same message and to display prior results.

## Duplicate Email Handling

The scanner compares each email's Gmail message ID and a `sender|subject` signature against existing log entries. If a match exists, it prints the previous scan result and skips reprocessing the message.

## Extending the Project

### Add new detection rules

- Edit `PHISHING_PATTERNS` in `phishing_detector.py`.
- Add new categories and regex patterns.
- Update `get_threat_summary()` to provide readable descriptions.

### Improve URL detection

- Modify `bad_tlds` in `url_checker.py`.
- Add additional URL heuristics or domain reputation checks.

### Enhance scoring

- Adjust `threat_weights` in `risk_score.py`.
- Add custom risk factors for attachments, sender reputation, or past history.

### Add actions

- Extend `actions.py` with new functions such as quarantining, notifying administrators, or saving evidence reports.
- Call those actions from `gmail_reader.py` after threats are detected.

## Security Recommendations

- Move the VirusTotal API key out of `virustotal_checker.py` and into a secure environment variable.
- Validate and sanitize any user-provided input.
- Limit Gmail API scope to just what is needed.
- Review OAuth consent and access permissions carefully.

## Known Limitations

- The tool relies on pattern-based rules and may generate false positives.
- HTML parsing is basic and may miss deeply nested content.
- VirusTotal checks use a single API key and do not currently handle rate limits.
- It does not currently quarantine or block messages automatically.
- No formal unit tests are included yet.

## Future Enhancements

- Add OAuth and Gmail API scope configuration.
- Implement better HTML email parsing with `BeautifulSoup`.
- Add attachment inspection and metadata analysis.
- Support multi-account scanning or service account integration.
- Provide a web dashboard or report export.
- Replace the hardcoded VirusTotal key with secure configuration.

## Contact and Use

Use this tool for authorized security testing and email analysis only. Always get consent before scanning someone else’s mailbox.
