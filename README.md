# LeakGuard

Personal exposure cleanup. You give it a keyword you made up (one that only you use) and your email addresses. It then:

1. **finds** your leaked emails, usernames, accounts, breaches, pastes, public pages and data-broker entries, using many OSINT tools,
2. **blocks** unwanted mail in Gmail,
3. **removes** what can be removed (opt-outs, GDPR erasure, account deletion, search removal) and tracks each item until it is verified gone,
4. **monitors** for new exposures whenever you run it.

It only acts on identities you have claimed. It is tested in a private lab with a fictional identity first, then run on the internet against allowed sources.

## Your data stays out of the repository
| What | Where |
|---|---|
| Your keyword, emails, usernames (`leakguard init`, `leakguard add`) | `~/.config/leakguard/identities.yaml` (mode 600) |
| Mail allow/block lists, Gmail OAuth token | `~/.config/leakguard/` |
| Scan database, raw tool output, reports, Takeout exports | `~/.local/share/leakguard/` |
| API keys | `.env` (git-ignored) |

`leakguard install-hook` adds a git pre-commit hook. It rejects any commit containing your keyword, emails, usernames or identities found by scans. `leakguard leakcheck` runs the same check by hand.

## Setup
```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[lab,browser,dev]'
cp .env.example .env && chmod 600 .env   # API keys: HIBP, IntelX, Brave, GitHub (optional)
.venv/bin/leakguard doctor               # lists missing OSINT tools and how to install them
python3 scripts/patch_ghunt.py           # fixes GHunt 2.3.4 crashes (re-run after upgrading GHunt)
.venv/bin/leakguard init                 # enter your keyword and emails (asked interactively)
.venv/bin/leakguard install-hook         # block commits that would leak them
.venv/bin/leakguard sources -p internet  # which sources are ready (keys, tools, allowed)
```

## Commands
All commands take `-p lab` (fictional lab identity, no internet) or `-p internet`.

### Your identity
| Command | What it does |
|---|---|
| `leakguard init` | Enter your keyword, emails, usernames and name (private file, mode 600) |
| `leakguard add -e old@mail.com -u oldname` | Declare more of your own identities (e.g. old addresses); claimed at once |
| `leakguard identities` | List identities: claimed, candidate, rejected |
| `leakguard claim 3 4` / `leakguard reject 5` | Confirm candidates are yours, or not. Only claimed ones are scanned or cleaned |

### Discovery
| Command | What it does |
|---|---|
| `leakguard expand` | Search the keyword itself; propose candidate emails/usernames |
| `leakguard scan` | Deep scan of every claimed identity (all sources) |
| `leakguard scan -s holehe -s ghunt` | Only some sources (repeatable `-s`) |
| `leakguard findings [--status new] [--verdict open]` | List findings with their ID |
| `leakguard mark <id> --as <verdict> --note "..."` | Your verdict: `open` (clean up: deactivate/delete), `protect` (your account to keep and secure), `accepted` (no action), `false_positive` |
| `leakguard report` | Markdown + JSON report in `~/.local/share/leakguard/reports/` |
| `leakguard password-check` | Is a password in known breaches? (HIBP Pwned Passwords; only a 5-character hash prefix leaves your machine) |
| `leakguard sources` | Sources, what they handle, and whether they can run |

Every source run is logged with status (`ok`, `partial`, `skipped`, `error`, `scope_blocked`), HTTP status, the service's reply or the tool's own output, and timing. Only API key values are masked. A `partial` run (for example rate-limited sites) never marks earlier findings as gone. Sherlock and Maigret hits are checked against a random username, and sites that "find" any name are dropped.

### Mail
| Command | What it does |
|---|---|
| `leakguard block` | Dry run: classify the inbox and list what would be blocked |
| `leakguard block --apply` | Move unwanted mail (Junk, Trash, LeakGuard/Review). Nothing is deleted for good |
| `leakguard block --apply --filters` | Also sync your blocklist to Gmail server-side filters |
| `leakguard lab-import <takeout.mbox>` | Lab: load a copy of your Google Takeout mail into the lab mailbox |
| `leakguard block -p lab --owner-copy --since 0` | Lab: run the rules on that copy and compare with Gmail's own Spam label |

Your allow/block lists and leak date go in `~/.config/leakguard/mail_rules.yaml`, which is created on the first `block`.

### Removal (phase 3)
Actions are planned from your verdicts: `open` findings become removal actions (one per site, index or broker,
merging every tool's evidence), `protect` findings become one security checklist, the rest are skipped.

| Command | What it does |
|---|---|
| `leakguard remove plan` | Build or refresh the actions from your findings |
| `leakguard remove list [--state requested] [--due]` | Actions and their state (`--due`: follow-up date passed) |
| `leakguard remove show <id>` | Steps, contact, linked findings and history of one action |
| `leakguard remove draft <id>` | Write the email request (account deletion / GDPR erasure, leak removal, paste report, opt-out) and print it |
| `leakguard remove send <id> --confirm` | Send it (lab: Mailpit; internet: from your Gmail). Refused if the contact is not verified |
| `leakguard remove form <id> [--confirm]` | Fill an opt-out form in a headless browser and screenshot it; submits only with `--confirm` |
| `leakguard remove contact <id> <email or URL>` | Set a contact you checked yourself |
| `leakguard remove add "Site" -i <your email/username> [--url ...] [--email ...] --why "..."` | Add an action for an account no scan found (e.g. known from a mail) |
| `leakguard remove done <id> --note "..."` | You did a manual step (deleted the account, finished the checklist) |
| `leakguard remove set <id> acknowledged --note "..."` | Record a reply from the site |
| `leakguard remove check [<id>]` | Re-run the sources behind an action; `verified` only when every linked finding is gone |
| `leakguard remove catalog-update` | Download the JustDeleteMe dataset (delete-account links for many sites) |

States: planned → drafted → requested → acknowledged → removed → verified (also `done` for manual steps and
checklists, `skipped`). Illegal jumps are refused and every change is kept in the action's history. Drafts and
screenshots are private (`~/.local/share/leakguard/`, mode 600) and never contain leaked passwords.

### Repository safety
| Command | What it does |
|---|---|
| `leakguard leakcheck` | Fail if any file git would commit contains your private identity |
| `leakguard install-hook` | Run that check before every commit |
| `leakguard doctor` | Which external OSINT tools are installed |

The lab walkthrough is in [lab/README.md](lab/README.md).

## Status
| Phase | What | State |
|---|---|---|
| 0 | Skeleton, tool check | done |
| 1 | Expand + discovery | done: 19 sources; first internet scans run |
| 2 | Mail blocking | done: lab corpus, real-mail copy matches Gmail spam 9/9 with 0 false positives |
| 3 | Removal workflow | lab done; internet plan checked (catalog fixes from real data), actions in progress |
| 4 | Monitor + scorecard | |
| 5 | Internet cleanup | in progress (discovery) |
