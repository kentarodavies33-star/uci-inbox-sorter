#!/usr/bin/env python3
"""UCI Inbox Sorter - Step 1: rule-based sorting + basic scam flagging.

Reads new emails in your UCI Gmail inbox, decides what each one is using
rules.json, then labels (and optionally archives) it.

Runs as a DRY RUN by default. Add --apply to actually change your inbox.
"""

import argparse
import json
import os
import re
from collections import Counter
from email.utils import parseaddr

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
PROCESSED_LABEL = "UCI-Sorter-Processed"
HEADERS = ["From", "Reply-To", "Subject", "List-Unsubscribe"]


# ---------------------------------------------------------------- Gmail access

def get_service():
    """Log in with OAuth (opens a browser the first time) and return a Gmail client."""
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build

    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as f:
            f.write(creds.to_json())
    return build("gmail", "v1", credentials=creds)


def list_new_message_ids(service, max_messages):
    """Inbox emails the sorter hasn't looked at yet."""
    query = f"in:inbox -label:{PROCESSED_LABEL}"
    ids, page_token = [], None
    while len(ids) < max_messages:
        resp = service.users().messages().list(
            userId="me", q=query, pageToken=page_token,
            maxResults=min(100, max_messages - len(ids)),
        ).execute()
        ids += [m["id"] for m in resp.get("messages", [])]
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return ids


def fetch_email(service, msg_id):
    """Get just the headers + preview text (fast, no full body download)."""
    msg = service.users().messages().get(
        userId="me", id=msg_id, format="metadata", metadataHeaders=HEADERS
    ).execute()
    headers = {h["name"].lower(): h["value"] for h in msg["payload"].get("headers", [])}
    return parse_email(msg_id, headers, msg.get("snippet", ""))


def parse_email(msg_id, headers, snippet):
    from_name, from_addr = parseaddr(headers.get("from", ""))
    _, reply_to = parseaddr(headers.get("reply-to", ""))
    return {
        "id": msg_id,
        "from_name": from_name.lower(),
        "from_addr": from_addr.lower(),
        "reply_to": reply_to.lower(),
        "subject": headers.get("subject", ""),
        "snippet": snippet,
        "has_unsubscribe": "list-unsubscribe" in headers,
    }


def ensure_labels(service, names):
    """Create any missing labels (including parents like 'UCI Sorter') and return name -> id."""
    existing = {l["name"]: l["id"] for l in
                service.users().labels().list(userId="me").execute().get("labels", [])}
    wanted = []
    for name in names:
        parts = name.split("/")
        wanted += ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
    for name in dict.fromkeys(wanted):  # dedupe, keep order (parents first)
        if name not in existing:
            created = service.users().labels().create(userId="me", body={
                "name": name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            }).execute()
            existing[name] = created["id"]
    return existing


# ---------------------------------------------------------------- Classification

def domain(addr):
    return addr.rsplit("@", 1)[-1] if "@" in addr else ""


def is_uci(addr):
    d = domain(addr)
    return d == "uci.edu" or d.endswith(".uci.edu")


def find_word(words, text):
    """First word/phrase from `words` that appears in `text` as a whole word."""
    for w in words:
        if re.search(r"(?<!\w)" + re.escape(w) + r"(?!\w)", text):
            return w
    return None


def scam_score(email, cfg):
    """Add up warning signs. Returns (score, list of reasons)."""
    text = f"{email['subject']} {email['snippet']}".lower()
    score, reasons = 0, []

    hits = [k for k in cfg["keywords"] if find_word([k], text)]
    if hits:
        score += len(hits)
        reasons.append("keywords: " + ", ".join(hits[:3]))

    reply, sender = email["reply_to"], email["from_addr"]
    if reply and domain(reply) != domain(sender) and not (is_uci(reply) and is_uci(sender)):
        score += 2
        reasons.append(f"replies go to {domain(reply)}")

    if find_word(cfg["impersonation_words"], email["from_name"]) and not is_uci(sender):
        score += 2
        reasons.append("sounds like UCI staff but isn't @uci.edu")

    if re.search(r"\$\s?\d{2,}.{0,20}(per|/|a)\s?(week|hour|hr|wk)", text):
        score += 1
        reasons.append("pay-per-week/hour offer")

    return score, reasons


def match_category(email, cat):
    """Return why this email fits the category, or None."""
    sender = f"{email['from_name']} {email['from_addr']}"
    subject = email["subject"].strip().lower()
    for prefix in cat.get("subject_starts_with", []):
        if subject.startswith(prefix):
            return f"subject starts with '{prefix}'"
    for s in cat.get("from_contains", []):
        if s in sender:
            return f"sender has '{s}'"
    word = find_word(cat.get("subject_contains", []), email["subject"].lower())
    if word:
        return f"subject has '{word}'"
    if cat.get("has_unsubscribe") and email["has_unsubscribe"]:
        return "has unsubscribe link (mass mail)"
    return None


def is_trusted(addr, trusted_domains):
    d = domain(addr)
    return any(d == t or d.endswith("." + t) for t in trusted_domains)


def classify(email, rules):
    """Scam check first (skipped for trusted services like Canvas),
    then categories in the order they appear in rules.json."""
    scam = rules["scam"]
    if not is_trusted(email["from_addr"], scam.get("trusted_domains", [])):
        score, reasons = scam_score(email, scam)
        if score >= scam["threshold"]:
            return scam, f"scam score {score}: " + "; ".join(reasons)
    for cat in rules["categories"]:
        reason = match_category(email, cat)
        if reason:
            return cat, reason
    return None, "no rule matched"


# ---------------------------------------------------------------- Main

def main():
    p = argparse.ArgumentParser(description="Sort a UCI Gmail inbox.")
    p.add_argument("--apply", action="store_true",
                   help="Actually label/archive emails (default is a dry run).")
    p.add_argument("--max", type=int, default=50, help="Max emails to process.")
    p.add_argument("--rules", default="rules.json")
    args = p.parse_args()

    with open(args.rules) as f:
        rules = json.load(f)

    service = get_service()
    ids = list_new_message_ids(service, args.max)
    if not ids:
        print("No new emails to sort.")
        return

    label_ids = {}
    if args.apply:
        names = [c["label"] for c in rules["categories"]]
        names += [rules["scam"]["label"], PROCESSED_LABEL]
        label_ids = ensure_labels(service, names)

    print(("APPLYING" if args.apply else "DRY RUN") + f" - {len(ids)} emails\n")
    counts = Counter()
    for mid in ids:
        email = fetch_email(service, mid)
        cat, reason = classify(email, rules)
        name = cat["name"] if cat else "Keep in inbox"
        counts[name] += 1
        print(f"[{name:<15}] {email['subject'][:55]:<55} <- {reason}")

        if args.apply:
            add, remove = [label_ids[PROCESSED_LABEL]], []
            if cat:
                add.append(label_ids[cat["label"]])
                if cat.get("archive"):
                    remove.append("INBOX")
            service.users().messages().modify(
                userId="me", id=mid,
                body={"addLabelIds": add, "removeLabelIds": remove},
            ).execute()

    print("\nSummary:")
    for name, n in counts.most_common():
        print(f"  {name}: {n}")
    if not args.apply:
        print("\nNothing was changed. Run again with --apply to sort for real.")


if __name__ == "__main__":
    main()
