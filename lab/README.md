# Lab

Everything here runs without internet, inside the training lab scope (127.0.0.1 and 192.168.1.248/29).

## Mock OSINT service
Fake versions of HIBP, IntelX, Google Programmable Search, LeakCheck, psbdmp, Gravatar, the keyservers,
GitHub search and a data broker (with an opt-out form). The data is in `mock_osint/data/seed.json`.

```bash
.venv/bin/python lab/mock_osint/app.py          # binds 127.0.0.1:5055 only
rm -f lab/mock_osint/state.json                 # undo opt-outs done through the mock broker
```

Seeded scenario for the keyword `zorblat`:
| Identity | Role |
|---|---|
| `zorblat11@seclab.test` | seed (claimed from the start) |
| `zorblat.old@seclab.test`, `zorblat_x`, `zorblat11`, `zorblat` | yours: found by `expand`, claim them |
| `zorblat.backup@seclab.test` | yours: only found by the deep `scan` (Maigret profile bio) |
| `zorblat-fanclub` | **not yours**: reject it, and check it is never scanned |

## Fixtures
`fixtures/<tool>/<identity>.<csv|json>` is recorded output in each tool's real format (holehe, h8mail,
GHunt, Mosint, socialscan, Sherlock, Maigret, Blackbird, SpiderFoot). In the lab profile the tools never
run, because they contact real websites. Their fixtures are parsed instead.

## End-to-end run
```bash
rm -f data/lab.sqlite
.venv/bin/leakguard scan --stage keyword -p lab   # 5 candidates
.venv/bin/leakguard identities -p lab
.venv/bin/leakguard claim 3 4 5 7 -p lab && .venv/bin/leakguard reject zorblat-fanclub -p lab   # IDs or values
.venv/bin/leakguard scan --stage identities -p lab   # finds the backup email as a new candidate
.venv/bin/leakguard report -p lab
```

## Mail blocking (GreenMail on 192.168.1.250)
`mail_corpus.py` holds 22 messages for the fictional owner, each with its expected verdict: 10 legit
(including look-alikes such as a real "Google" security alert and a security-code mail), 8 spam
(sextortion, phishing, failed DMARC, scams, mass BCC), 2 on the owner blocklist and 2 sign-up newsletters
first seen after the leak. The owner lists are in `mail_rules.yaml`.

```bash
.venv/bin/python lab/seed_mail.py --reset   # empty the lab mailbox, send the corpus
.venv/bin/leakguard block -p lab            # dry run: shows the verdicts, changes nothing
.venv/bin/leakguard block -p lab --apply    # moves: Junk 8, Trash 2, LeakGuard.Review 2, INBOX keeps 10
```
`tests/test_classifier.py` checks the same corpus offline.

## Your real mail, copied into the lab (`--owner-copy`)
Tests the rules on a copy of your own mail without touching Gmail. The copy goes into the separate GreenMail
mailbox `owner-copy@seclab.test` over TLS. It uses your private identity and `~/.config/leakguard/mail_rules.yaml`.
1. Export your mail at takeout.google.com: "Deselect all", tick **Mail**, format mbox, then download the zip.
2. Extract the mbox into your private data folder, then delete the zip:
   `mkdir -p ~/.local/share/leakguard/takeout && unzip -j ~/Downloads/takeout-*.zip '*.mbox' -d ~/.local/share/leakguard/takeout/`
3. `leakguard lab-import ~/.local/share/leakguard/takeout/<file>.mbox` (newest 2000 from the last year by default)
4. `leakguard block -p lab --owner-copy --since 0 --limit 2000`: a dry run, plus a comparison with Gmail's own Spam label.
   `--apply` moves messages in the lab copy only.
GreenMail keeps mail in memory, so restarting the container wipes the copy.

## Removal workflow (phase 3)
The lab catalog (`removal_catalog.json`) points every contact at fake `@*.seclab.test` addresses, which go to
Mailpit and are never delivered, or at the mock broker's opt-out form. `fixtures/jdm_sites.json` is a small
sample in the JustDeleteMe format.

```bash
.venv/bin/leakguard remove status -p lab            # refresh the plan: one action per site/index/broker
.venv/bin/leakguard remove do <id> -p lab           # email action: the draft (e.g. Intelligence X)
.venv/bin/leakguard remove do <id> --confirm -p lab #   ... sent to Mailpit
.venv/bin/leakguard remove do <id> -p lab           # broker: screenshot of the filled form
.venv/bin/leakguard remove do <id> --confirm -p lab #   ... submitted
.venv/bin/leakguard remove check <id> -p lab        # the broker listing is gone, so the action is verified
rm -f lab/mock_osint/state.json                     # undo the broker opt-out
```
