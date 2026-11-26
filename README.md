# LeakGuard

Personal exposure cleanup. You give it a keyword you made up (one that only you use) and your email addresses. It then:

1. **finds** your leaked emails, usernames, accounts, breaches, pastes, public pages and data-broker entries, using many OSINT tools,
2. **blocks** unwanted mail in Gmail,
3. **removes** what can be removed (account deletion, GDPR erasure, leak-index removal, opt-outs) and tracks each item until a re-scan shows it gone,
4. **monitors** for new exposures whenever you run it.

It only acts on identities you have claimed, and nothing leaves your machine (no email, no form) without `--confirm`.
The full guide is **[docs/MANUAL.md](docs/MANUAL.md)**; the lab walkthrough is [lab/README.md](lab/README.md).

## Your data stays out of the repository
| What | Where |
|---|---|
| Your keyword, emails, usernames | `~/.config/leakguard/identities.yaml` (mode 600) |
| Mail allow/block lists, Gmail OAuth token | `~/.config/leakguard/` |
| Scan database, raw tool output, reports, drafts, screenshots, Takeout exports | `~/.local/share/leakguard/` |
| API keys | `.env` (git-ignored) |

## Setup
```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[lab,browser,dev]'
cp .env.example .env && chmod 600 .env   # API keys: HIBP, IntelX, Brave, GitHub (optional)
python3 scripts/patch_ghunt.py           # fixes GHunt 2.3.4 crashes (re-run after upgrading GHunt)
.venv/bin/leakguard init                 # your keyword and emails
.venv/bin/leakguard install-hook         # block commits that would leak them
.venv/bin/leakguard doctor -p internet   # tools installed? sources ready?
```

## Commands
All commands take `-p lab` (fictional identity, no internet) or `-p internet`. `leakguard <command> --help` shows every option.

| Group | Command | What it does |
|---|---|---|
| Identity | `init` | Enter your keyword, emails, usernames, name |
| | `identities` | List identities: claimed, candidate, rejected |
| | `claim ID\|VALUE...` | Mark identities as yours, by ID or value; an unknown value is added as yours |
| | `reject ID\|VALUE...` | Mark identities as not yours; an unknown value is added as rejected |
| Discovery | `scan [--stage keyword\|identities] [-s SOURCE]` | Search the keyword, propose candidates, deep-scan claimed identities |
| | `findings [--status] [--verdict]` | List findings with IDs |
| | `mark ID... --as open\|protect\|accepted\|false_positive` | Your verdict: clean up, keep and secure, no action, not yours |
| | `report` | Markdown + JSON report |
| | `password-check` | Is a password in known breaches? (only a 5-character hash prefix leaves your machine) |
| Removal | `remove status [ID]` | Refresh the plan from your findings; list actions or show one |
| | `remove do ID [--confirm]` | Perform it: email (draft / send), form (fill / submit), manual (steps) |
| | `remove set ID [STATE] [--note] [--contact]` | Record progress, a site's reply, or a contact you checked |
| | `remove add SITE -i IDENTITY` | Add an action for an account no scan found |
| | `remove check [ID]` | Re-run the sources behind actions; `verified` when every finding is gone |
| Mail | `block [--apply] [--filters]` | Classify the inbox; move unwanted mail (dry run by default) |
| | `lab-import MBOX` | Lab: load a Google Takeout copy of your mail |
| Setup | `doctor` | External tools and source readiness |
| | `leakcheck` / `install-hook` | Refuse commits that contain your private identity |

## Status
| Phase | What | State |
|---|---|---|
| 0 | Skeleton, tool check | done |
| 1 | Discovery | done: 19 sources, run on real data |
| 2 | Mail blocking | done: real-mail copy matches Gmail spam 9/9, 0 false positives |
| 3 | Removal workflow | done: lab + real plan; actions waiting on sites |
| 4 | Monitor + scorecard | next |
| 5 | Internet cleanup | in progress |
