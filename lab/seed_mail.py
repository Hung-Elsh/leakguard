"""Fill (or reset) the lab GreenMail mailbox of the fictional owner with lab/mail_corpus.py.

  .venv/bin/python lab/seed_mail.py            # send the corpus
  .venv/bin/python lab/seed_mail.py --reset    # empty every folder first (lab mailbox only)

Lab profile only: the scope guard refuses any host outside 192.168.1.248/29.
"""

import argparse
import smtplib
import sys
from pathlib import Path

from imapclient import IMAPClient

sys.path.insert(0, str(Path(__file__).parent))
from mail_corpus import CORPUS, ME, build  # noqa: E402

from leakguard import config  # noqa: E402
from leakguard.mail.imap_backend import empty_mailbox  # noqa: E402
from leakguard.scope import ScopeGuard  # noqa: E402


def reset(cfg: dict) -> None:
    with IMAPClient(cfg["host"], port=cfg["port"], ssl=False, timeout=20) as c:
        c.login(cfg["user"], cfg["password"])
        empty_mailbox(c)
        print("reset: mailbox emptied")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reset", action="store_true")
    args = ap.parse_args()
    s = config.load("lab")
    cfg, smtp = s.mail, s.mail["seed_smtp"]
    guard = ScopeGuard(s)
    guard.check_host(cfg["host"], "mail")
    guard.check_host(smtp["host"], "mail")
    if args.reset:
        reset(cfg)
    with smtplib.SMTP(smtp["host"], smtp["port"], timeout=20) as conn:
        for entry in CORPUS:
            conn.send_message(build(entry), to_addrs=[ME])     # envelope always to the lab owner (BCC case)
    print(f"sent {len(CORPUS)} messages to {ME} via {smtp['host']}:{smtp['port']}")


if __name__ == "__main__":
    main()
