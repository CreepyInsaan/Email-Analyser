def quarantine_email(service, message_id):

    service.users().messages().modify(
        userId='me',
        id=message_id,
        body={
            'addLabelIds': ['SPAM']
        }
    ).execute()

    print("[+] Email moved to spam")