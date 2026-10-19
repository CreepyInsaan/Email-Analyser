import datetime
import html
import os
import base64
import re
from google.auth.exceptions import RefreshError

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from phishing_detector import detect_phishing, get_threat_summary
from risk_score import calculate_risk
from url_checker import extract_urls, analyze_urls
from virustotal_checker import VirusTotalError, check_url
from siem_logger import log_event, load_logged_events


SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def authenticate_gmail():

    creds = None

    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file(
            'token.json',
            SCOPES
        )

    if not creds or not creds.valid:

        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except RefreshError:
                # Refresh token invalid (revoked/expired). Remove stored token
                # and fall back to full OAuth flow to obtain new credentials.
                try:
                    if os.path.exists('token.json'):
                        os.remove('token.json')
                except Exception:
                    pass

                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json',
                    SCOPES
                )

                creds = flow.run_local_server(port=0)

        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json',
                SCOPES
            )

            creds = flow.run_local_server(port=0)

        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    service = build('gmail', 'v1', credentials=creds)

    return service


def get_message_body(payload):
    """Extract the plain text body from Gmail message payload."""
    body = ""

    def html_to_text(html_content):
        links = re.findall(
            r'''href\s*=\s*["'](https?://[^"']+)["']''',
            html_content,
            re.IGNORECASE
        )
        text = re.sub(r'<[^>]+>', '', html_content)
        return text + " " + " ".join(html.unescape(link) for link in links)

    def extract_from_parts(parts):
        """Recursively extract text from message parts."""
        text_content = ""
        for part in parts:
            if part.get('mimeType') == 'text/plain' and 'body' in part and 'data' in part['body']:
                try:
                    text_content += base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
                except:
                    pass
            elif part.get('mimeType') == 'text/html' and 'body' in part and 'data' in part['body']:
                try:
                    html_content = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
                    text_content += html_to_text(html_content)
                except:
                    pass
            elif 'parts' in part:
                text_content += extract_from_parts(part['parts'])
        return text_content

    if 'body' in payload and 'data' in payload['body']:
        try:
            body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')
            if payload.get('mimeType') == 'text/html':
                body = html_to_text(body)
        except:
            body = ""
    elif 'parts' in payload:
        body = extract_from_parts(payload['parts'])

    return body


def get_attachment_names(payload):
    """Return filenames exposed in Gmail message-part metadata."""
    filenames = []

    def collect(parts):
        for part in parts:
            filename = part.get('filename')
            if filename:
                filenames.append(filename)
            if 'parts' in part:
                collect(part['parts'])

    if 'parts' in payload:
        collect(payload['parts'])
    return filenames


def get_emails():
    service = authenticate_gmail()

    next_page_token = None
    total = 0
    phishing_count = 0
    suspicious_count = 0
    low_risk_count = 0

    logged_message_ids, logged_signatures, logged_details = load_logged_events()

    print(f"Live email scan started at {datetime.datetime.now()}")
    print("=" * 60)

    while True:
        request = service.users().messages().list(
            userId='me',
            maxResults=100,
            pageToken=next_page_token
        )

        results = request.execute()
        messages = results.get('messages', [])

        if not messages:
            break

        for message in messages:
            msg = service.users().messages().get(
                userId='me',
                id=message['id']
            ).execute()

            headers = msg['payload']['headers']
            subject = ""
            sender = ""

            for header in headers:
                if header['name'] == 'Subject':
                    subject = header['value']
                if header['name'] == 'From':
                    sender = header['value']

            signature = f"{sender}|{subject}"
            previous_key = msg['id'] if msg['id'] in logged_message_ids else signature
            if msg['id'] in logged_message_ids or signature in logged_signatures:
                previous = logged_details.get(previous_key, {})
                print(f"[SKIP] Email already checked: {sender} | {subject}")
                print("Previous result:")
                print(f"  FROM   : {previous.get('sender', sender)}")
                print(f"  SUBJECT: {previous.get('subject', subject)}")
                print(f"  RISK   : {previous.get('risk_score', 'N/A')}/100")
                threat_text = previous.get('threat', 'No threat details available')
                print(f"  THREAT : {threat_text}")
                print("=" * 50)
                continue

            # Extract email body
            body = get_message_body(msg['payload'])
            attachment_names = get_attachment_names(msg['payload'])
            combined_text = subject + " " + sender + " " + body

            # Extract and analyze URLs
            urls = extract_urls(combined_text)
            suspicious_urls = analyze_urls(urls)
            
            # Check URLs with VirusTotal
            malicious_count = 0
            malicious_urls = []
            unscanned_urls = []
            url_scan_errors = []
            for url in urls:
                try:
                    malicious = check_url(url)
                except VirusTotalError as exc:
                    url_scan_errors.append({"url": url, "error": str(exc)})
                    continue

                if malicious is None:
                    unscanned_urls.append(url)
                elif malicious > 0:
                    malicious_count += malicious
                    malicious_urls.append({
                        "url": url,
                        "malicious_engines": malicious
                    })

            # Detect phishing threats
            detected_threats = detect_phishing(
                combined_text, sender, subject, urls, attachment_names
            )
            if malicious_urls:
                detected_threats["VirusTotal Malicious URL"] = malicious_urls
            threat_summary = get_threat_summary(detected_threats)

            # Calculate risk score
            risk_score = calculate_risk(detected_threats, suspicious_urls, sender, subject)

            # Determine status
            if risk_score >= 70:
                status = "PHISHING"
                phishing_count += 1
            elif risk_score >= 40:
                status = "SUSPICIOUS"
                suspicious_count += 1
            elif risk_score >= 20:
                status = "LOW RISK"
                low_risk_count += 1
            else:
                status = "SAFE"

            # Use the threat summary as reasons
            reasons = threat_summary
            
            # Log to SIEM
            log_event(
                sender,
                subject,
                risk_score,
                " | ".join(reasons) if reasons else "No threats",
                message_id=msg['id'],
                status=status,
                threat_categories=list(detected_threats),
                suspicious_urls=suspicious_urls,
                malicious_urls=malicious_urls,
                unscanned_urls=unscanned_urls,
                attachments=attachment_names,
                url_scan_errors=url_scan_errors
            )

            # Format output with timestamp
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] LIVE EMAIL SCAN")
            print("=" * 50)
            print(f"FROM     : {sender}")
            print(f"SUBJECT  : {subject}")
            print()
            print(f"RISK     : {risk_score}/100")
            print(f"STATUS   : {status}")
            print()
            
            # Show detailed threat breakdown
            print("THREAT BREAKDOWN:")
            print(f"  - Detected Threats: {len(detected_threats)}")
            print(f"  - Suspicious URLs: {len(suspicious_urls)}")
            print(
                f"  - Malicious URLs (VirusTotal): {len(malicious_urls)} "
                f"(reported by {malicious_count} engines)"
            )
            print(f"  - URLs not found in VirusTotal: {len(unscanned_urls)}")
            if url_scan_errors:
                print(f"  - VirusTotal lookup errors: {len(url_scan_errors)}")
            print()
            
            if detected_threats:
                print("THREAT DETAILS:")
                for threat in detected_threats:
                    print(f"  ✗ {threat}")
            
            if suspicious_urls:
                print("SUSPICIOUS URLs:")
                for url in suspicious_urls:
                    print(f"  ⚠ {url}")

            if malicious_urls:
                print("MALICIOUS URLs (VirusTotal):")
                for finding in malicious_urls:
                    print(
                        f"  ⚠ {finding['url']} "
                        f"({finding['malicious_engines']} engines)"
                    )

            if url_scan_errors:
                print("VirusTotal lookup errors:")
                for error in url_scan_errors:
                    print(f"  ! {error['error']}: {error['url']}")
            
            if (
                not detected_threats
                and not suspicious_urls
                and not malicious_count
                and not url_scan_errors
            ):
                print("No threats detected")
            
            print("=" * 50)

            total += 1

        next_page_token = results.get('nextPageToken')
        if not next_page_token:
            break

    # Print analysis summary
    end_time = datetime.datetime.now()
    print(f"\n{'='*60}")
    print("ANALYSIS SUMMARY")
    print(f"{'='*60}")
    print(f"Completed at: {end_time}")
    print(f"Total emails analyzed: {total}")
    print(f"Phishing emails: {phishing_count}")
    print(f"Suspicious emails: {suspicious_count}")
    print(f"Low risk emails: {low_risk_count}")
    print(f"Safe emails: {total - phishing_count - suspicious_count - low_risk_count}")
    print(f"{'='*60}")

    print(f"\nTotal messages displayed: {total}")


if __name__ == "__main__":
    try:
        get_emails()
    except KeyboardInterrupt:
        print("\n\n[!] Email scan interrupted by user")
        print("[+] Shutting down gracefully...")
        exit(0)