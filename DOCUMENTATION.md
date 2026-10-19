# Gmail Threat Analyzer Documentation

Gmail Threat Analyzer is a Python command-line application that retrieves Gmail messages, checks them for heuristic phishing and other threat indicators, calculates a risk score, and records results in a local JSON Lines file.

## Project structure

- `gmail_reader.py` — OAuth authentication, Gmail message retrieval, analysis workflow, and console output.
- `phishing_detector.py` — pattern-based message, sender, URL, and attachment-filename indicators.
- `url_checker.py` — HTTP(S) URL extraction and suspicious-host/URL-structure analysis.
- `virustotal_checker.py` — VirusTotal URL reputation lookups.
- `risk_score.py` — threat-category weighting and risk score calculation.
- `siem_logger.py` — append-only scan logging and duplicate-scan lookup.
- `actions.py` — helper for adding the Gmail `SPAM` label; it is not invoked automatically by the scanner.
- `requirements.txt` — Python dependencies.
- `README.md` — quick-start instructions.
- `logs/siem_logs.json` — generated scan log.
- `credentials.json` and `token.json` — local OAuth credentials and token; keep private and do not commit.

## Requirements and installation

- Python 3.10 or newer
- A Google account and Gmail API access
- A Google Cloud OAuth 2.0 Desktop app client
- A VirusTotal API key for URL reputation lookups

From the project directory, create and activate a virtual environment, then install dependencies:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

For Command Prompt, activate the environment with `venv\Scripts\activate.bat`.

In Google Cloud Console, enable the Gmail API, create an OAuth 2.0 Desktop app client, and save its downloaded credentials as `credentials.json` in the project directory.

Set the VirusTotal API key in the environment. In PowerShell, this sets it for the current session:

```powershell
$env:VIRUSTOTAL_API_KEY = "your-api-key"
```

Do not store the key in source code or commit it. The scanner attempts a VirusTotal lookup for every extracted URL. If the key is missing or a lookup fails, the error is reported and logged; this is not treated as a clean result.

## Running the scanner

```powershell
python gmail_reader.py
```

On first run, a browser window opens for Gmail authorization. The resulting token is stored in `token.json` and reused on later runs. The application requests the `https://www.googleapis.com/auth/gmail.modify` scope; review this access carefully before consenting.

The scanner retrieves messages through Gmail's messages list API (up to 100 per page, following subsequent pages when present). It does not specify an inbox-only query.

## Scan workflow

For each message not identified as previously scanned, the application:

1. Reads the sender and subject headers.
2. Extracts plain-text or HTML body text from the message payload, and collects attachment filenames from MIME-part metadata.
3. Extracts unique HTTP(S) URLs from the sender, subject, and extracted body text.
4. Analyzes URLs for suspicious top-level domains, IP-address hosts, embedded URL credentials, and punycode hostnames.
5. Requests VirusTotal reputation for each extracted URL.
6. Applies phishing-pattern, sender-domain, URL, and attachment-filename checks.
7. Calculates a risk score, prints the findings, and appends an event to `logs/siem_logs.json`.

The tool does not download attachment files or inspect their contents. It does not automatically quarantine, delete, or otherwise modify messages. `actions.py` defines a separate helper for adding the `SPAM` label, but the scan workflow does not call it.

## Detection behavior

The detector uses regular-expression patterns and heuristics. Categories include phishing and spam wording, urgency and social engineering, sender-domain spoofing and typosquatting, impersonation, suspicious or obfuscated links, credential theft, OAuth consent abuse, business email compromise, invoice/payment fraud, ransomware and malware wording, and other patterns defined in `PHISHING_PATTERNS` in `phishing_detector.py`.

Attachment analysis is filename-only. Certain executable, script, and other risky extensions are flagged as `Malware Attachments`; common document and archive extensions are flagged as `Malicious Attachments`. These are indicators based on filenames, not a verdict about file contents.

URL analysis and phishing-pattern analysis are separate checks. A suspicious URL can contribute to the score even when no matching message-text pattern is found. VirusTotal results are also considered: URLs with one or more malicious engine detections are included as a threat category.

## Risk score

`risk_score.py` adds the configured weight for each detected threat category, adds 8 points per suspicious URL, and adds a small increment for multiple categories and selected high-risk combinations. The result is capped at 100.

| Score | Classification |
| --- | --- |
| 70–100 | `PHISHING` |
| 40–69 | `SUSPICIOUS` |
| 20–39 | `LOW RISK` |
| 0–19 | `SAFE` |

These classifications are heuristic and should not be interpreted as proof that a message is malicious or safe.

## VirusTotal and privacy

When configured, the application sends each extracted URL to VirusTotal's URL analysis endpoint. Consider VirusTotal's data-handling terms and organizational policy before scanning messages that may contain sensitive or confidential URLs. VirusTotal API errors, including a missing key, are recorded as lookup errors and do not establish that a URL is safe. API rate limits or network failures may make lookups unavailable.

The scan log can contain sender addresses, subjects, threat details, URLs, attachment filenames, message IDs, and lookup errors. Treat it as sensitive data. The repository's `.gitignore` excludes `credentials.json`, `token.json`, and `logs/`; continue to keep these files private.

## Logging and duplicate handling

`siem_logger.py` appends one JSON object per line to `logs/siem_logs.json`. An event includes the timestamp, sender, subject, risk score, threat summary, status, threat categories, suspicious URLs, malicious URLs, URLs not found in VirusTotal, attachment filenames, and VirusTotal lookup errors. The Gmail message ID is included when available.

At startup, the scanner loads prior events and skips a message when either its Gmail message ID or its `sender|subject` signature has already been logged. The signature fallback can also cause distinct messages with the same sender and subject to be skipped. To intentionally analyze messages again, remove or archive the relevant log entries before a scan.

## Detection scope and limitations

- Pattern-based checks can produce false positives and may miss new or context-dependent attacks.
- Attachment contents are not downloaded or scanned; a risky extension is not proof of malware.
- HTML is converted to text with basic tag removal and link extraction, not a full security-focused HTML parser.
- Some patterns (such as spear-phishing, email bombing, OAuth consent, and mailbox-rule abuse) indicate suspicious wording only. The application does not analyze mailbox-wide volume, account settings, or actual mailbox rules.
- VirusTotal availability depends on the API key, network connectivity, and service limits.
- A `SAFE` classification means the configured checks did not produce a high score; it is not a guarantee of safety.

Use the tool only with mailboxes you own or are authorized to analyze, and review findings before taking action.

## Extending the project

- Add or tune detection patterns in `PHISHING_PATTERNS` in `phishing_detector.py`.
- Update `get_threat_summary()` in the same module when adding a category that needs a readable console summary.
- Adjust category weights and risk factors in `risk_score.py`.
- Adjust URL extraction or suspicious-host indicators in `url_checker.py`.
- Extend logging fields in `siem_logger.py` and its call site in `gmail_reader.py` together so persisted events remain consistent.
- If adding message actions, call them explicitly from the scan workflow and make their effects clear to the operator.
