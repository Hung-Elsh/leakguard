"""Lab mail corpus for the fictional owner zorblat11@seclab.test, with the verdict each message should get.

Used by lab/seed_mail.py (sends it to GreenMail) and tests/test_classifier.py (offline check).
The owner lists used for the expected verdicts are in lab/mail_rules.yaml (leak date 2023-01-01).
"""

from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from datetime import datetime, timezone

ME = "zorblat11@seclab.test"
OLD, NEW = datetime(2022, 5, 3, 9, tzinfo=timezone.utc), datetime(2026, 11, 20, 9, tzinfo=timezone.utc)
LIST = {"List-Unsubscribe": "<mailto:unsubscribe@list.test>", "List-Id": "<weekly.list.test>"}
AUTH_OK = {"Authentication-Results": "mx.seclab.test; dkim=pass header.d=devnews.test; spf=pass; dmarc=pass"}

CORPUS = [
    # ---- should be kept ------------------------------------------------------------------------
    dict(id="mom", frm="Mom <mom@family.seclab.test>", subject="Dinner on Sunday?", body="Come home early.",
         expect="keep"),
    dict(id="bank", frm="Lab Bank <alerts@bank.seclab.test>", subject="Your monthly statement",
         body="Your statement is ready. Verify your account details online.", expect="keep"),
    dict(id="friend-old", frm="Minh <friend.minh@seclab.test>", date=OLD, subject="long time no see",
         body="How are you?", expect="keep"),
    dict(id="friend-new", frm="Minh <friend.minh@seclab.test>", subject="Coffee next week?",
         body="Free on Tuesday?", expect="keep"),                       # known: wrote before the leak
    dict(id="news-old", frm="Tech Weekly <news@techweekly.seclab.test>", date=OLD, subject="Issue #120",
         body="This week in tech.", headers=LIST, expect="keep"),
    dict(id="news-new", frm="Tech Weekly <news@techweekly.seclab.test>", subject="Issue #301",
         body="This week in tech.", headers=LIST, expect="keep"),
    dict(id="gh-code", frm="GitHub Lab <noreply@github-lab.seclab.test>", subject="Your security code",
         body="Your code is 123456.", expect="keep"),
    dict(id="recruiter", frm="HR <hr@company.seclab.test>", subject="Interview schedule",
         body="Please confirm your slot.", headers={"Reply-To": "recruiter@jobs.company.seclab.test"},
         expect="keep"),                                                # same base domain: not a mismatch
    dict(id="google-real", frm="Google <no-reply@accounts.google.test>", subject="Security alert",
         body="New sign-in on Linux.", expect="keep"),                  # brand matches sender domain
    dict(id="plain-unknown", frm="someone@somewhere.test", subject="Hi", body="Hello there.",
         expect="keep"),                                                # no evidence: never block on a guess
    dict(id="relay-fail-final-pass", frm="Zing Lab <noreply@games.seclab.test>", subject="Password reset request",
         body="Someone asked to reset your password.", expect="keep",
         headers={"Authentication-Results": "mx.google.com; dkim=pass header.i=@games.seclab.test; spf=pass; dmarc=pass",
                  "ARC-Authentication-Results": "i=1; mx.microsoft.com 1; spf=fail; dmarc=fail"}),
    dict(id="dev-newsletter", frm="Dev News <do-not-reply@hello.devnews.test>",
         subject="Issue 300: You won't believe this", body="Survey winner announced. Bitcoin ETFs explained.",
         headers={**LIST, **AUTH_OK}, expect="label"),   # scam words ignored; only "new list after leak" review

    # ---- should be blocked -----------------------------------------------------------------------
    dict(id="sextortion-1", frm="anon@mailer-xyz.test", subject="Security notice",
         body="I know your password: hunter22. I recorded you. Pay 500 USD in bitcoin.", expect="spam"),
    dict(id="sextortion-2", frm="Hacker <x@darkmail.test>", subject="your password is compromised",
         body="I hacked your device via your webcam. Send 0.05 BTC to my wallet within 48 hours.", expect="spam"),
    dict(id="paypal-spoof", frm="PayPal Security <service@paypa1-support.test>", subject="Account limited",
         body="Log in to restore access.", expect="spam"),
    dict(id="reply-to-phish", frm="IT Helpdesk <it-desk@univ-lab.test>",
         subject="Password expires today - verify now", body="Click to keep your mailbox.",
         headers={"Reply-To": "collect@grab-creds.test"}, expect="spam"),
    dict(id="auth-fail", frm="promo@shop-unknown.test", subject="Big sale", body="50% off everything.",
         headers={"Authentication-Results": "mx.seclab.test; spf=fail smtp.mailfrom=shop-unknown.test; dmarc=fail"},
         expect="spam"),
    dict(id="inheritance", frm="Barrister James <james@legal-uk.test>", subject="Inheritance for you",
         body="You are the beneficiary of 4.5 million USD.", expect="spam"),
    dict(id="crypto", frm="giveaway@coins-free.test", subject="Crypto giveaway ends today",
         body="Send 0.1 to receive 1.", expect="spam"),
    dict(id="bulk-bcc", frm="offers@bulkmail.test", to="undisclosed-recipients:;", subject="Hello dear",
         body="Special offer for you.", expect="spam"),
    dict(id="random-domain", frm="scwfsupport@nkgbkagcfbfhoatsodwsqpes.test",
         subject="A simple addition to your daily routine", body="Try it today.", expect="spam"),
    dict(id="random-subdomains", frm="ywam.9752@4782v1.3mi3bm.ms5xjc.test",
         subject="The routine getting attention", body="Read more.", expect="spam"),
    dict(id="storage-scam", frm="Cloud Alerts <alerts@cloudsafe-mail.test>",
         subject="Your photos will be deleted tonight", body="Upgrade now to keep them.", expect="spam"),
    dict(id="blocked-addr", frm="deals@spammy-shop.test", subject="Deals!", body="Buy now.", expect="trash"),
    dict(id="blocked-domain", frm="promo@casino-bonus.test", subject="Free spins", body="Play now.",
         headers=LIST, expect="trash"),
    dict(id="list-after-leak-1", frm="Random Store <newsletter@random-store.test>", subject="New arrivals",
         body="Shop the collection.", headers=LIST, expect="label"),
    dict(id="list-after-leak-2", frm="Dating Site <weekly@dating-site.test>", subject="5 people viewed you",
         body="See who.", headers=LIST, expect="label"),
]


def build(entry: dict) -> EmailMessage:
    m = EmailMessage()
    m["From"] = entry["frm"]
    m["To"] = entry.get("to", ME)
    m["Subject"] = entry["subject"]
    m["Date"] = format_datetime(entry.get("date", NEW))
    m["Message-ID"] = make_msgid(idstring=entry["id"], domain="corpus.seclab.test")
    m["X-Lab-Expect"] = entry["expect"]
    for k, v in (entry.get("headers") or {}).items():
        m[k] = v
    m.set_content(entry["body"])
    return m
