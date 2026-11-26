"""Offline check of the mail classifier on the lab corpus: every message gets its expected verdict.
Wrongly blocking real mail is the costly mistake, so the corpus includes several look-alike legit mails."""

import sys
from pathlib import Path

import pytest

from leakguard.mail.message import parse
from leakguard.mail.rules import Classifier, OwnerLists
from leakguard.paths import LAB_MAIL_RULES, ROOT

sys.path.insert(0, str(ROOT / "lab"))
from mail_corpus import CORPUS, ME, build  # noqa: E402


@pytest.fixture(scope="module")
def verdicts():
    msgs = [parse(e["id"], build(e).as_bytes()) for e in CORPUS]
    clf = Classifier(OwnerLists.load(LAB_MAIL_RULES, {ME}))
    clf.learn_known(msgs)
    return {m.uid: clf.classify(m) for m in msgs}


@pytest.mark.parametrize("entry", CORPUS, ids=[e["id"] for e in CORPUS])
def test_expected_verdict(entry, verdicts):
    v = verdicts[entry["id"]]
    assert v.action == entry["expect"], f"{entry['id']}: got {v.action} by {v.rule or 'no rule'} ({v.reasons})"


def test_allowlist_beats_rules():
    # the bank mail contains "verify your account", but the allowlisted domain wins
    e = next(x for x in CORPUS if x["id"] == "bank")
    clf = Classifier(OwnerLists.load(LAB_MAIL_RULES, {ME}))
    assert clf.classify(parse("b", build(e).as_bytes())).rule == "allowlist"


def test_gmail_labels_decoding():
    from leakguard.mail.message import SPAM_LABELS, gmail_labels
    raw = "=?UTF-8?Q?Spam,Ch=C6=B0a_=C4=91=E1=BB=8Dc?=\r\n =?UTF-8?Q?,H=E1=BB=99p_th=C6=B0_=C4=91=E1=BA=BFn?="
    labels = gmail_labels(raw)
    assert "spam" in labels and "chưa đọc" in labels and "hộp thư đến" in labels
    assert labels & SPAM_LABELS
    assert gmail_labels("Inbox,Category Updates") == {"inbox", "category updates"}


@pytest.mark.parametrize("domain,expected", [
    ("4782v1.3mi3bm.ms5xjc.us", True), ("uf0s27.z7s594.u965et.us", True),
    ("fhcqczxscolpgmqcidarfdqt.com", True), ("nkgbkagcfbfhoatsodwsqpes.com", True),
    ("16personalities.com", False), ("hello.stackoverflow.email", False), ("vng.com.vn", False),
    ("accounts.google.com", False), ("1password.com", False), ("em1234.sendgrid.net", False),
    ("bounce.em5678.sg2.example.com", False), ("mail.vietcombank.com.vn", False),
])
def test_random_domain(domain, expected):
    from leakguard.mail.rules import looks_random
    assert looks_random(domain) is expected
