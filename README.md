# Gmail Threat Analyzer

Gmail Threat Analyzer is a Python command-line tool that scans Gmail messages for phishing indicators, suspicious URLs, and potentially risky attachment filenames. It assigns each message a heuristic risk score and appends the results to a local JSON Lines log.

## Features

- Authenticates to Gmail using OAuth 2.0 and retrieves mailbox messages.
- Analyzes message sender, subject, body text, URLs, and attachment filenames.
- Flags phishing and other suspicious patterns, sender-domain indicators, and URL structures.
- Looks up extracted URLs with VirusTotal when an API key is configured.
- Displays a risk score and classification for each newly analyzed message.
- Logs scan results and skips messages already present in the log.

## Requirements

- Python 3.10 or newer
- A Google account with the Gmail API enabled
- Gmail OAuth client credentials
- A VirusTotal API key for URL reputation lookups

## Setup

1. Clone or download this repository and open a terminal in the project directory.
2. Create and activate a virtual environment. In PowerShell:

   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

   In Command Prompt, activate it with `venv\Scripts\activate.bat`.

3. Install the project dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

4. In Google Cloud Console, enable the Gmail API and create an OAuth 2.0 **Desktop app** client. Save the downloaded credentials file as `credentials.json` in the project directory.
5. Set the VirusTotal API key in the environment before running a scan. In PowerShell, for the current session:

   ```powershell
   $env:VIRUSTOTAL_API_KEY = "your-api-key"
   ```

   Do not put the API key in source code or commit it. Without this key, Gmail scanning continues, but VirusTotal lookups are unavailable and are recorded as errors.

## Run

```powershell
python gmail_reader.py
```

On the first run, a browser window opens for Gmail authorization and the resulting OAuth token is saved as `token.json`. Keep both `credentials.json` and `token.json` private.

The scanner requests the Gmail `gmail.modify` OAuth scope. Review the requested access before granting consent.

## How a scan works

1. Authenticates with Gmail and retrieves messages.
2. Extracts the sender, subject, body text, URLs, and attachment filenames.
3. Applies pattern-based phishing and sender checks, and analyzes URLs for suspicious hosts or structures.
4. Submits each extracted URL to VirusTotal when the API key is configured. VirusTotal lookup errors are displayed and logged; they are not treated as clean results.
5. Calculates a risk score, displays the result, and appends the scan details to `logs/siem_logs.json`.
6. Skips messages already recorded in the log and displays their previous result.

## Risk classifications

Scores range from 0 to 100:

| Score | Classification |
| --- | --- |
| 70–100 | `PHISHING` |
| 40–69 | `SUSPICIOUS` |
| 20–39 | `LOW RISK` |
| 0–19 | `SAFE` |

The score combines detected threat categories and suspicious URLs. It is a heuristic indicator, not a guarantee that a message is safe or malicious.

## Logs and generated files

- `token.json` is created after Gmail authorization.
- `logs/siem_logs.json` is created when scan results are logged. It contains one JSON object per line, including message details, risk results, URL findings, attachment filenames, and any VirusTotal lookup errors.
- Existing log entries are used to avoid scanning the same message again.

These files can contain sensitive information. Keep them private and do not commit them to Git. The repository's `.gitignore` excludes credentials, tokens, and logs.

## Limitations and privacy

- Detection is based on heuristics and can produce false positives or miss new threats. Review findings before taking action.
- Attachment filenames may be checked for risky extensions, but attachment files are not downloaded or scanned.
- VirusTotal receives every extracted URL when lookups are enabled. Review VirusTotal's data-handling terms and your organization's policies before scanning sensitive messages.
- A missing API key, network problem, or VirusTotal error makes the lookup unavailable; it does not establish that a URL is safe.
- Findings do not automatically quarantine, delete, or otherwise modify messages.
- Use only with mailboxes you own or are authorized to analyze.

## Troubleshooting

- **OAuth or Gmail API errors:** Confirm the Gmail API is enabled, `credentials.json` is a valid Desktop app OAuth client file in the project directory, and the account has authorized access. If the saved token is no longer valid, remove `token.json` and authorize again.
- **Missing Python package:** Activate the virtual environment and run `python -m pip install -r requirements.txt`.
- **VirusTotal lookup errors:** Confirm `VIRUSTOTAL_API_KEY` is set in the same terminal session, the key is valid, and network access is available. VirusTotal may also enforce API limits.
- **Previously scanned messages are skipped:** Review `logs/siem_logs.json`; remove or archive the log only if you intentionally want to scan messages again.

## Project files

- `gmail_reader.py` — Gmail authentication and scan workflow
- `phishing_detector.py` — phishing and sender indicator rules
- `url_checker.py` — URL extraction and suspicious URL analysis
- `virustotal_checker.py` — VirusTotal URL lookups
- `risk_score.py` — risk score calculation
- `siem_logger.py` — JSON Lines logging and duplicate-scan support
- `actions.py` — email action helper
- `requirements.txt` — Python dependencies
- `DOCUMENTATION.md` — additional project and implementation details
