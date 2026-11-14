"""Tests for the sorting rules. Run with:  pytest"""

import json

from sorter import classify, parse_email

with open("rules.json") as f:
    RULES = json.load(f)


def make(from_, subject, snippet="", reply_to=None, unsubscribe=False):
    headers = {"from": from_, "subject": subject}
    if reply_to:
        headers["reply-to"] = reply_to
    if unsubscribe:
        headers["list-unsubscribe"] = "<mailto:unsub@example.com>"
    return parse_email("test", headers, snippet)


def category(email):
    cat, _ = classify(email, RULES)
    return cat["name"] if cat else None


def test_canvas_is_important():
    e = make("Canvas <notifications@instructure.com>", "ICS 31: Assignment 3 posted")
    assert category(e) == "Important"


def test_canvas_digest_with_other_reply_to_is_not_scam():
    # Real case from my inbox: Canvas replies route through canvaslms.com
    e = make("UCI Canvas <notifications@instructure.com>", "Recent Canvas Notifications",
             reply_to="reply+abc@notifications.canvaslms.com")
    assert category(e) == "Important"


def test_gradescope_is_important():
    e = make("Gradescope <no-reply@gradescope.com>",
             "[Math 2A: Fall 2026 on Gradescope] Successfully submitted")
    assert category(e) == "Important"


def test_campus_invite_curly_apostrophe():
    e = make("UCI Events <events@uci.edu>", "You’re invited to a film screening")
    assert category(e) == "Clubs & Events"


def test_fake_professor_job_is_scam():
    e = make("Professor James Lee <jlee.office22@gmail.com>",
             "Part-time job opportunity",
             "Dear student, I need a remote assistant. $400 per week. Kindly text me.")
    assert category(e) == "Possible Scam"


def test_reply_to_mismatch_adds_up():
    e = make("UCI Helpdesk <alerts@uci-support.net>", "Mailbox full",
             "Verify your account now", reply_to="fix@random-domain.ru")
    assert category(e) == "Possible Scam"


def test_club_email():
    e = make("ASUCI <asuci@uci.edu>", "Free food at the Student Center!")
    assert category(e) == "Clubs & Events"


def test_newsletter_by_unsubscribe_header():
    e = make("UCI News <news@uci.edu>", "This week at UCI", unsubscribe=True)
    assert category(e) == "Mass Mail"


def test_real_professor_stays_in_inbox():
    e = make("Jane Smith <jsmith@ics.uci.edu>", "Re: question about lecture 5")
    assert category(e) == "Always Keep"  # replies always stay in the inbox

    e = make("Jane Smith <jsmith@ics.uci.edu>", "Question about lecture 5")
    assert category(e) is None


def test_uci_mailing_list_reply_to_is_not_suspicious():
    e = make("Dept Advisor <advisor@ics.uci.edu>", "Quick note",
             reply_to="ics-list@uci.edu")
    assert category(e) is None


# --- Always Keep: these must never be archived, even with an unsubscribe link.
# Senders/subjects taken from my real inbox.

def test_zotalert_police_activity_stays_even_with_unsubscribe():
    e = make("zotALERT <uci@zotalert.em.uci.edu>", "Police Activity - Final Update",
             unsubscribe=True)
    assert category(e) == "Always Keep"


def test_bei_shift_email_stays():
    e = make("GROUP Brain Exercise Initiative <bei@uci.edu>",
             "BEI Shift Tomorrow 11/13 at 1:30-2:30pm", unsubscribe=True)
    assert category(e) == "Always Keep"


def test_bei_weekly_announcements_are_mass_mail():
    e = make("BEI at UCI <bei@uci.edu>", "BEI Week 7 Announcements!", unsubscribe=True)
    assert category(e) == "Mass Mail"


def test_microsoft_365_notice_stays():
    e = make('"Office of Information Technology" <zotmail@uci.edu>',
             "Microsoft 365 Services Restored", unsubscribe=True)
    assert category(e) == "Always Keep"


def test_marketing_deadline_is_not_important():
    e = make("Career Center <careers@uci.edu>",
             "Build Your Healthcare Future - application deadline Friday",
             unsubscribe=True)
    assert category(e) == "Mass Mail"


# --- Replies are real conversations: never archive them.

def test_reply_about_club_stays_in_inbox():
    # Real case: was being archived as Clubs & Events because of the word "club".
    e = make("Campus Rec <rec@uci.edu>", "Re: Issue with 2 Bodybuilding Club Registrations")
    assert category(e) == "Always Keep"


def test_scam_reply_is_still_flagged():
    e = make("Professor James Lee <jlee.office22@gmail.com>", "RE: Part-time job opportunity",
             "Dear student, I need a remote assistant. $400 per week. Kindly text me.")
    assert category(e) == "Possible Scam"


# --- Daily summary email

from datetime import datetime

from sorter import build_summary

WHEN = datetime(2026, 11, 14, 8, 0)


def result(email):
    cat, reason = classify(email, RULES)
    name = cat["name"] if cat else "Keep in inbox"
    return (email, name, reason, bool(cat and cat.get("archive")))


def test_summary_counts_and_scam_warning():
    results = [
        result(make("Canvas <notifications@instructure.com>", "ICS 31: Assignment 3 posted")),
        result(make("ASUCI <asuci@uci.edu>", "Free food at the Student Center!")),
        result(make("Professor James Lee <jlee.office22@gmail.com>", "Part-time job opportunity",
                    "Dear student, I need a remote assistant. $400 per week. Kindly text me.")),
    ]
    subject, body = build_summary(results, WHEN)
    assert subject == "UCI Sorter: 3 sorted, 1 possible scam"
    assert "Sorted 3 new emails (1 archived, 2 left in your inbox)" in body
    assert "POSSIBLE SCAMS" in body and "jlee.office22@gmail.com" in body
    assert "ICS 31: Assignment 3 posted" in body  # listed under Important
    assert "Sat Nov 14, 2026 at 8:00 AM" in body


def test_summary_with_no_new_email():
    subject, body = build_summary([], WHEN)
    assert subject == "UCI Sorter: 0 sorted"
    assert "No new emails" in body
    assert "POSSIBLE SCAMS" not in body
