# Gmail Threat Analyzer

Gmail Threat Analyzer is a Python email security tool for scanning Gmail messages and identifying phishing, spoofing, and suspicious URL behavior.

## What this project does

- Reads Gmail messages via the Gmail API
- Extracts sender, subject, and email body text
- Detects phishing patterns, spoofing, and social engineering
- Analyzes URLs and marks suspicious domains
- Checks URLs against VirusTotal for malicious reputation
- Computes a risk score for each email
- Logs results to `logs/siem_logs.json`

## Files in this repository

- `gmail_reader.py` - main script that authenticates with Gmail, reads messages, and runs analysis
- `phishing_detector.py` - detection rules and phishing heuristics
- `url_checker.py` - URL extraction and suspicious domain detection
- `virustotal_checker.py` - VirusTotal URL reputation lookup
- `risk_score.py` - risk scoring engine for email threat levels
- `siem_logger.py` - logging and duplicate-scan prevention
- `actions.py` - helper functions for email actions
- `credentials.json` - Gmail OAuth credentials (not included in repo)
- `token.json` - OAuth token generated after first run
- `logs/siem_logs.json` - scan result log file

## Requirements

- Python 3.10+
- Gmail API credentials

## Recommended dependencies

Install the required libraries:

```powershell
python -m pip install --upgrade pip
python -m pip install \
  google-api-python-client \
  google-auth-httplib2 \
  google-auth-oauthlib \
  beautifulsoup4 \
  colorama \
  validators \
  tldextract \
  requests
```

## Setup

1. Create a Python virtual environment:

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

2. Install the dependencies above.

3. Enable the Gmail API in Google Cloud Console.
4. Create OAuth 2.0 credentials and download `credentials.json` to this folder.

## Running the tool

```powershell
python gmail_reader.py
```

On first run, Gmail will ask for OAuth permission and create `token.json`.

## Install dependencies from requirements

After creating and activating the virtual environment, install packages with:

```powershell
pip install -r requirements.txt
```

```
## How the scan works

1. Authenticate with Gmail.
2. List inbox messages.
3. Extract message headers and body text.
4. Extract URLs from email content.
5. Run phishing detection rules.
6. Check suspicious URLs with VirusTotal.
7. Compute a risk score and display the result.
8. Log findings to `logs/siem_logs.json`.

## Risk output

The tool assigns a score from 0 to 100 and classifies emails as:

- `PHISHING`
- `SUSPICIOUS`
- `LOW RISK`
- `SAFE`

## Important notes

- Do not commit `credentials.json`, `token.json`, or `logs/` to Git.
- Protect your Gmail credentials and OAuth token.
- This tool is intended for authorized testing only.

## Recommended `.gitignore`

```gitignore
venv/
.vscode/
__pycache__/
credentials.json
token.json
logs/
```

## Troubleshooting

- If Gmail authentication fails, verify your OAuth credentials and Gmail API settings.
- If a dependency is missing, reinstall with `pip install -r requirements.txt` after creating the file.
- If the scanner can’t read messages, ensure the Gmail account is accessible and the token is valid.
