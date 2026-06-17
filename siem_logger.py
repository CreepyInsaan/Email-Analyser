import json
import os
from datetime import datetime


def load_logged_events():
    logged_ids = set()
    logged_signatures = set()
    logged_details = {}
    path = "logs/siem_logs.json"

    if not os.path.exists(path):
        return logged_ids, logged_signatures, logged_details

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            sender = entry.get("sender", "")
            subject = entry.get("subject", "")
            detail = {
                "sender": sender,
                "subject": subject,
                "risk_score": entry.get("risk_score"),
                "threat": entry.get("threat"),
                "timestamp": entry.get("timestamp")
            }

            if entry.get("message_id"):
                msg_id = entry["message_id"]
                logged_ids.add(msg_id)
                logged_details[msg_id] = detail
            else:
                signature = f"{sender}|{subject}"
                logged_signatures.add(signature)
                logged_details[signature] = detail

    return logged_ids, logged_signatures, logged_details


def log_event(
    sender,
    subject,
    risk,
    threat,
    message_id=None
):

    if not os.path.exists("logs"):
        os.makedirs("logs", exist_ok=True)

    log = {
        "timestamp": str(datetime.now()),
        "sender": sender,
        "subject": subject,
        "risk_score": risk,
        "threat": threat
    }

    if message_id:
        log["message_id"] = message_id

    with open(
        "logs/siem_logs.json",
        "a",
        encoding="utf-8"
    ) as f:

        f.write(json.dumps(log) + "\n")