# Gmail Threat Analyzer

Gmail Threat Analyzer is a Python-based email security tool designed to scan your Gmail inbox for phishing, spoofing, malicious links, and other suspicious content.

> For full developer documentation and architecture details, see `DOCUMENTATION.md`.

## Overview

This project connects to Gmail using the Gmail API, reads messages, and applies multiple detection techniques to identify threats. It generates a consolidated risk score per email and highlights indicators such as impersonation, URL manipulation, and social engineering.

## Key Features

- Gmail API integration for inbox scanning
- Rule-based phishing detection
- URL and domain reputation analysis
- VirusTotal URL reputation checks
- Risk scoring from safe to phishing
- Duplicate email skip using SIEM log history
- Previous result summary shown for already-checked emails
- Modular architecture for detection and scoring
- Command-line execution with live output

## What It Detects

- Social engineering and urgency tactics
- Email spoofing and sender impersonation
- Malicious or shortened URLs
- Suspicious domains and typosquatting
- Credential harvesting attempts
- Strange attachments or hidden malicious content

## How It Works

1. `gmail_reader.py` connects to Gmail using OAuth and reads recent messages from the inbox.
2. The raw email data is passed through `phishing_detector.py` to identify suspicious patterns and behaviors.
3. `url_checker.py` examines links and domains found in email bodies to flag phishing URLs and lookalike domains.
4. `virustotal_checker.py` checks suspicious URLs against VirusTotal for known malicious detections.
5. `risk_score.py` consolidates detected threats into a single score, making it easy to classify email risk.
6. `siem_logger.py` logs email results and prevents duplicate checks by skipping already-processed messages while showing the previous result.
7. `actions.py` supports any follow-up operations, such as logging, quarantining, or generating alerts.

## Detection Strategy

- Sender analysis: checks for mismatched sender addresses and display names.
- Content inspection: looks for phishing keywords, urgency signals, and suspicious HTML or attachment indicators.
- URL validation: detects shortened links, known bad domains, and hidden redirect patterns.
- Reputation checks: leverages heuristic rules to identify typosquatting and URL obfuscation.

## Extension Guide

- Add new phishing rules in `phishing_detector.py` for custom email patterns.
- Update scoring details in `risk_score.py` to change how threats contribute to the final risk value.
- Expand URL heuristics in `url_checker.py` to cover new attack techniques.
- Use `actions.py` to integrate quarantine, notification, or reporting workflows.

## Installation

1. Install Python 3.10+.
2. Create a virtual environment (recommended):

```bash
python -m venv venv
venv\Scripts\Activate.ps1   # PowerShell
venv\Scripts\activate.bat   # Command Prompt
```

3. Install required packages:

```bash
pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib beautifulsoup4 colorama validators tldextract scikit-learn dkimpy pyspf
```

If you want, create a `requirements.txt` file with the same packages for reuse:

```text
google-api-python-client
google-auth-httplib2
google-auth-oauthlib
beautifulsoup4
colorama
validators
tldextract
scikit-learn
dkimpy
pyspf
```

4. Configure Gmail API access:
   - Create a project in the Google Cloud Console
   - Enable the Gmail API
   - Create OAuth 2.0 credentials
   - Download `credentials.json` into the project folder

## Usage

Run the main analyzer:

```bash
python gmail_reader.py
```

The first time you run the tool, it will open a browser window or provide a local URL for Gmail OAuth authentication. After successful sign-in, `token.json` is created automatically.

The tool will:

1. Authenticate via the Gmail API
2. Read emails from the connected account
3. Analyze message headers, body, and URLs
4. Check suspicious URLs against VirusTotal
5. Assign a risk score to each message
6. Log results to `logs/siem_logs.json`
7. Skip duplicate checks for already-processed emails while showing prior results
8. Exit cleanly when stopped with Ctrl+C

## Example Output

```text
[2026-05-13 14:32:15] LIVE EMAIL SCAN
--------------------------------------------------
FROM     : suspicious@sender.com
SUBJECT  : Urgent Account Verification

RISK     : 85 / 100
STATUS   : PHISHING

THREAT BREAKDOWN:
  - Detected Threats: 4
  - Suspicious URLs: 1
  - Malicious URLs (VirusTotal): 1

THREAT DETAILS:
  ✗ Sender address mismatch
  ✗ High urgency / credential request
  ✗ Suspicious URL detected
  ✗ Domain typo / lookalike detected

SUSPICIOUS URLs:
  ⚠ http://bit.ly/...
--------------------------------------------------
```

If an email was already processed, the tool now displays the prior result and then skips reprocessing it.

## Supported Gmail Scopes

- `https://www.googleapis.com/auth/gmail.readonly`
- `https://www.googleapis.com/auth/gmail.modify`

If your current OAuth consent only allows read access, the analyzer can still scan messages but may not perform mailbox modifications.

## Project Files

- `gmail_reader.py` - Main Gmail integration and scanning workflow
- `phishing_detector.py` - Detection rules for phishing and suspicious content
- `risk_score.py` - Risk scoring engine and threat aggregation
- `url_checker.py` - URL and domain safety analysis
- `actions.py` - Email action handling and response utilities
- `credentials.json` - Gmail API credentials file (not included in repo)
- `token.json` - Stored OAuth token after initial authentication
- `Requirement` - Dependency installation guide

## Configuration

- `credentials.json`: OAuth client credentials from Google Cloud.
- `token.json`: Created automatically after first OAuth sign-in.

> Keep `credentials.json` and `token.json` secure. Do not commit them to version control.

## Troubleshooting

- If Gmail authentication fails, verify that the Gmail API is enabled and the OAuth credentials are correct.
- If dependencies are missing, reinstall with `pip install -r requirements.txt` after creating one or install packages manually.
- If the script cannot access email, ensure the account allows Gmail API access and the token is valid.

## Notes

- This project is intended for educational and research purposes.
- Always verify suspicious emails manually before acting on them.

## License

Use this project responsibly and only on accounts or systems for which you have permission.
