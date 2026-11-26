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
| Your keyword, emails, usernames (`leakguard init`) | `~/.config/leakguard/identities.yaml` (mode 600) |
| Scan database, raw tool output, reports | `~/.local/share/leakguard/` |
| API keys | `.env` (git-ignored) |

`leakguard install-hook` adds a git pre-commit hook. It rejects any commit containing your keyword, emails, usernames or identities found by scans. `leakguard leakcheck` runs the same check by hand.

## Setup
```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[lab,browser,dev]'
cp .env.example .env               # fill in API keys
.venv/bin/leakguard doctor         # lists missing OSINT tools and how to install them
.venv/bin/leakguard init           # enter your keyword and emails (asked interactively)
.venv/bin/leakguard install-hook   # block commits that would leak them
```

## Use
```bash
leakguard expand -p internet       # search the keyword, propose candidate emails/usernames
leakguard identities -p internet   # review candidates
leakguard claim 3 4 -p internet    # confirm the ones that are yours (reject the rest)
leakguard scan -p internet         # deep scan of claimed identities
leakguard report -p internet       # Markdown + JSON report
```
The lab walkthrough is in [lab/README.md](lab/README.md).

## Status
| Phase | What | State |
|---|---|---|
| 0 | Skeleton, tool check | done |
| 1 | Expand + discovery (lab) | done: 18 sources, lab end-to-end passes |
| 2 | Mail blocking (lab) | next |
| 3 | Removal workflow (lab) | |
| 4 | Monitor + scorecard | |
| 5 | Internet cleanup | |
