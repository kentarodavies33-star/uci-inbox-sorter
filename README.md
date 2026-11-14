# UCI Inbox Sorter

A Python tool that cleans up a UC Irvine student Gmail inbox through the Gmail API.
Class emails and anything important stay in the inbox. Club spam and mass mail get
labeled and archived. Likely phishing and fake-job emails get flagged.

**Results on my own inbox:** sorted **1,194 emails** and archived **512 (43%)** of them
as clutter. It also flagged **12 possible scams**, and **244 class and deadline emails**
stayed in the inbox under an Important label.

| Category | Emails | What happens |
|---|---:|---|
| Mass Mail | 393 | labeled + archived |
| Important | 244 | labeled, stays in inbox |
| Clubs & Events | 119 | labeled + archived |
| Always Keep | 20 | labeled, stays in inbox |
| Possible Scam | 12 | labeled, stays in inbox so I can review it |
| No rule matched | 406 | left untouched |

## Example (dry run on real emails)

```
DRY RUN - 50 emails

[Important      ] Recent Canvas Notifications                <- sender has 'instructure.com'
[Important      ] [Math 2A on Gradescope] Successfully submi <- sender has 'gradescope'
[Always Keep    ] Police Activity - Final Update             <- sender has 'zotalert'
[Always Keep    ] Re: Issue with 2 Club Registrations        <- subject starts with 're:'
[Clubs & Events ] KARAOKE EVENT TONIGHT - 7:30 PM            <- subject has 'event'
[Clubs & Events ] You’re invited to a film screening         <- subject has 'invited'
[Mass Mail      ] UC Irvine In the News - Nov. 13, 2026      <- subject has 'in the news'
[Mass Mail      ] Now serving BOGO lunch                     <- has unsubscribe link (mass mail)
[Keep in inbox  ] Document shared with you: "BIO SCI 35 ..." <- no rule matched

Summary:
  Mass Mail: 19
  Important: 10
  Keep in inbox: 9
  Clubs & Events: 7
  Always Keep: 5

Nothing was changed. Run again with --apply to sort for real.
```

## How it works
1. **Fetch.** Gets inbox emails the tool hasn't processed yet. It reads only the headers
   (From, Reply-To, Subject, List-Unsubscribe) and Gmail's short preview text, never the full body.
2. **Scam score.** Adds up warning signs, and an email that scores 3 or more is flagged:
   - suspicious phrases ("remote assistant", "gift card", "kindly", "verify your account"), +1 each
   - a Reply-To address on a different domain than the sender, +2
   - a display name that sounds like UCI staff ("Professor", "Financial Aid", "OIT") sent from a non-`@uci.edu` address, +2
   - "$400 per week"-style pay offers, +1

   Trusted services such as Canvas, Gradescope and Handshake skip this check to avoid false
   alarms. `uci.edu` is deliberately *not* trusted, because compromised student accounts
   are a common source of job scams.
3. **Categorize.** Checks the rules in `rules.json` in priority order. The first match wins:
   **Always Keep → Important → Clubs & Events → Mass Mail**.
4. **Apply.** Adds a nested label (`UCI Sorter/...`) and archives the email if that category
   has `"archive": true`. It also adds a `UCI-Sorter-Processed` label, so each email is
   only looked at once.

### Design decisions learned from real data
- **Replies are never archived.** "Re:" emails are real conversations, even when they
  mention a word like "club".
- **Always Keep beats the unsubscribe rule.** UCI Police alerts (zotALERT), work-shift
  emails and Microsoft 365 notices stay in the inbox even if they have an unsubscribe link.
- **"deadline" was removed from Important** because it pulled marketing emails
  ("Next Deadline Approaching!") into the inbox.
- **Trusted senders.** Canvas digests were being flagged as scams because their Reply-To
  is `canvaslms.com`, so known services skip the scam check.

## Daily schedule + summary email
The sorter can run on its own every morning and email you a summary like this:

```
Subject: UCI Sorter: 14 sorted, 1 possible scam

Sorted 14 new emails (9 archived, 5 left in your inbox):
  - Mass Mail: 7
  - Important: 3
  - Clubs & Events: 2
  - Possible Scam: 1
  - Keep in inbox: 1

POSSIBLE SCAMS (still in your inbox - don't reply, click links or send money):
  - Part-time job opportunity  (from jlee.office22@gmail.com; scam score 6: ...)

Important:
  - Assignment Graded: Quiz 4
  ...
```

It uses macOS **launchd**, the scheduler built into every Mac, so nothing extra needs to be installed.
```bash
bash schedule/install.sh          # every day at 8:00 AM
bash schedule/install.sh 21 30    # or pick a time (9:30 PM)
launchctl kickstart gui/$(id -u)/local.uci-inbox-sorter   # run it right now to test
bash schedule/uninstall.sh        # turn it off
```
- Scheduled runs use `--scheduled`, which means `--apply --email-summary --max 500`.
  They never open a browser. If the sign-in has expired, you get a Mac notification
  instead of a stuck job.
- If the Mac is asleep at the scheduled time, the job runs as soon as it wakes up.
- Output goes to `logs/sorter.log`.
- The summary is sent to your own address and marked as processed, so the sorter never sorts it.
- **Tip:** in Google Cloud's *Testing* mode, sign-ins expire every 7 days. For hands-off
  daily runs, set the OAuth consent screen to **In production**. For a personal app you
  don't need Google's verification; you'll just click through an "unverified app" warning
  once when you sign in again.

## Safety and privacy
- **Dry run by default.** Nothing changes unless you pass `--apply`.
- **Never deletes anything.** It only adds labels and archives, and both are reversible in Gmail.
- **Reads metadata only.** It never downloads email bodies or attachments.
- **Your secrets stay on your machine.** `credentials.json` and `token.json` are git-ignored.

## Setup (one time)
1. Go to https://console.cloud.google.com and create a project.
2. Enable the **Gmail API**: APIs & Services → Library → Gmail API → Enable.
3. Set up the **OAuth consent screen**: choose External and Testing, then add your
   `@uci.edu` address as a test user.
4. Create credentials: Credentials → Create → OAuth client ID → **Desktop app**.
   Download the JSON file and save it in this folder as `credentials.json`.
5. Install the dependencies:
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   ```

The first run opens a browser so you can sign in with your UCI account. In Testing mode
the sign-in expires after about 7 days. If sign-in fails, delete `token.json` and run again.

## Usage
```bash
python sorter.py                     # dry run: shows what it WOULD do
python sorter.py --apply             # actually labels and archives
python sorter.py --apply --max 1000  # first run on a big inbox (default is 50)
python sorter.py --email-summary     # also email yourself a summary
pytest                               # run the tests
```

All the sorting rules live in `rules.json`. Edit the senders and keywords there without
touching any code:
- `from_contains`: text to look for in the sender's name or address
- `subject_contains`: whole words or phrases to look for in the subject
- `subject_starts_with`: text the subject has to start with (for example `"re:"`)
- `has_unsubscribe`: match emails that have a List-Unsubscribe header

## Testing
The project has 19 `pytest` tests (including the summary email). Several of them come straight from misclassifications
in my real inbox: the Canvas scam false positive, a missed Gradescope email, a curly-apostrophe
"You’re invited", a reply that was being archived, and Police alerts that have an
unsubscribe link.

## Tech
Python · Gmail API · OAuth 2.0 · pytest · macOS launchd

## Roadmap
- [x] Rule-based sorting and scam scoring
- [x] Tested on a real inbox (1,194 emails)
- [x] Run automatically every day (launchd)
- [x] Daily summary email ("14 sorted, 1 possible scam")
- [ ] Machine-learning classifier (scikit-learn) trained on the emails it has already labeled
