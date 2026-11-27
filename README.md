# LeakGuard

Personal exposure cleanup. You give it a keyword you made up (one that only you use) and your email addresses. It then:

1. **finds** your leaked emails, usernames, accounts, breaches, pastes, public pages and data-broker entries, using many OSINT tools,
2. **blocks** unwanted mail in Gmail,
3. **removes** what can be removed (account deletion, GDPR erasure, leak-index removal, opt-outs) and tracks each item until a re-scan shows it gone,
4. **monitors** for new exposures whenever you run it.

It only acts on identities you have claimed, and nothing leaves your machine (no email, no form) without `--confirm`.
The full guide is **[docs/MANUAL.md](docs/MANUAL.md)**; the lab walkthrough is [lab/README.md](lab/README.md).

## How it works
```
keyword ─► discover (OSINT) ─► evaluate ─► your verdict ─► remove ─► verify by re-scan
                                                          └─► protect (checklist) · block (mail)
```
1. **Discover.** The keyword is searched (Brave, GitHub, IntelX) and every email or username containing it
   becomes a *candidate*; only those you `claim` are scanned further. Claimed identities go through 19 OSINT
   Framework sources: breach and leak indexes (HIBP, IntelX, LeakCheck, SpiderFoot/Leak-Lookup, h8mail,
   Mosint), account checkers (holehe, socialscan, Sherlock, Maigret, Blackbird), the Google account (GHunt),
   profiles and keys (Gravatar, PGP keyservers) and code (GitHub).
2. **Evaluate.** Findings from all tools are merged and rated by their evidence: high when a password, hash or
   credential compilation is involved or your email is on a public page, medium for breaches with unknown
   contents, low for accounts and exact name matches, info for look-alikes. Username hits are re-checked with a
   random control name to drop sites that "find" anyone; rate-limited checks are marked partial, never "clean".
3. **Your verdict** decides the plan: `open` (clean up), `protect` (your own account: keep and secure),
   `accepted`, `false_positive`.
4. **Remove.** One action per site. The JustDeleteMe dataset (about 2,700 sites, refreshed monthly) and a
   hand-checked catalog give each account's delete page or privacy contact. LeakGuard drafts the GDPR-style
   request, fills opt-out forms in a headless browser, or lists the steps; it sends or submits only with
   `--confirm`.
5. **Verify.** `remove check` re-runs the sources that found each item; it counts as removed only when they no
   longer see it. Every run and every step is logged for the dashboard.
6. **Monitor.** `monitor` (weekly via a systemd timer) repeats discovery, re-checks due removals, reopens any
   removal whose data came back, alerts on new exposures and keeps a scorecard and trend.

## Your data stays out of the repository
| What | Where |
|---|---|
| Your keyword, emails, usernames | `~/.config/leakguard/identities.yaml` (mode 600) |
| Mail allow/block lists, mail connection (`mail.yaml`, no passwords) | `~/.config/leakguard/` |
| Scan database, raw tool output, reports, drafts, screenshots, Takeout exports | `~/.local/share/leakguard/` |
| API keys, mail app password, Gmail sign-in | system keyring (`leakguard keys`); without one, `~/.config/leakguard/secrets.env` (mode 600) |

## Setup
```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[lab,browser,dev]'
python3 scripts/patch_ghunt.py           # fixes GHunt 2.3.4 crashes (re-run after upgrading GHunt)
.venv/bin/leakguard init                 # your keyword and emails
.venv/bin/leakguard install-hook         # block commits that would leak them
.venv/bin/leakguard keys set BRAVE_API_KEY   # API keys (HIBP, IntelX, Brave, GitHub; optional) go to the keyring
.venv/bin/leakguard doctor -p internet   # tools installed? sources ready?
```

## Desktop app
A native window (PySide6, in the style of Zenmap) for people who'd rather not use a terminal. No packages yet:
build it from source, which also shows you exactly what it does.
```bash
git clone git@github.com:Hung-Elsh/leakguard.git && cd leakguard && git switch native-app
python3 -m venv .venv && .venv/bin/pip install -e '.[gui,browser]'
.venv/bin/leakguard-app                  # first run: one "About you" screen, then the first check starts
.venv/bin/leakguard-app --practice       # practice mode: a made-up person, lab services only
.venv/bin/leakguard-app --add-to-menu    # optional: add LeakGuard to your application menu (your user only)
```
If it doesn't start and mentions "xcb", install Qt's one missing system library: `sudo apt install libxcb-cursor0`.
What's there so far: first-run setup; Start check (quick or full, everything or one address) with progress and
Stop; the Overview (cleaned-up ring, what needs you, what we're waiting for, trend, recent changes); **To do**
(is this you, what should we do with each find, your clean-up steps, what's waiting on sites; one click each,
with Undo); **Found** (everything found, searchable); **Clean-up** (every step, and adding a site we missed);
**Mail** (connect with an app password: Gmail, Yahoo, iCloud or your own servers; check, then move what you saw);
**Settings** (search-service keys, each tested before it's saved; extra checks with one-click installs and the
Google check's sign-in). Emails, forms and mail moves happen only after a screen that shows exactly what happens.
*View → Show the command line* shows the same check as a `leakguard` command. More pages follow (see Status).

## Commands
All commands take `-p lab` (fictional identity, no internet) or `-p internet`. `leakguard <command> --help` shows every option.

| Group | Command | What it does |
|---|---|---|
| Identity | `init` | Enter your keyword, emails, usernames, name |
| | `identities` | List identities: claimed, candidate, rejected |
| | `claim ID\|VALUE...` | Mark identities as yours, by ID or value; an unknown value is added as yours |
| | `reject ID\|VALUE...` | Mark identities as not yours; an unknown value is added as rejected |
| Discovery | `scan [--stage keyword\|identities] [-i IDENTITY] [-s SOURCE]` | Search the keyword, propose candidates, deep-scan claimed identities (`-i`: just one) |
| | `findings [--status] [--verdict]` | List findings with IDs |
| | `mark ID... --as open\|protect\|accepted\|false_positive` | Your verdict: clean up, keep and secure, no action, not yours |
| | `report [--final [--share]]` | Markdown + JSON report with the scorecard; `--final`: readable cleanup report; `--share`: identities masked |
| | `monitor [--quick] [--mail] [--schedule weekly]` | Scan, re-check due removals, report what changed, alert; `--schedule` writes a systemd timer |
| | `password-check` | Is a password in known breaches? (only a 5-character hash prefix leaves your machine) |
| Removal | `remove status [ID]` | Refresh the plan from your findings; list actions or show one |
| | `remove do ID [--confirm]` | Perform it: email (draft / send), form (fill / submit), manual (steps) |
| | `remove set ID [STATE] [--note] [--contact]` | Record progress, a site's reply, or a contact you checked |
| | `remove add SITE -i IDENTITY` | Add an action for an account no scan found |
| | `remove check [ID]` | Re-run the sources behind actions; `verified` when every finding is gone |
| Mail | `block [--apply] [--filters]` | Classify the inbox; move unwanted mail (dry run by default) |
| | `lab-import MBOX` | Lab: load a Google Takeout copy of your mail |
| Setup | `doctor` | External tools and source readiness |
| | `keys [set NAME \| forget NAME]` | List, save or remove API keys and the Gmail sign-in (system keyring) |
| | `leakcheck` / `install-hook` | Refuse commits that contain your private identity |

## Status
| Phase | What | State |
|---|---|---|
| 0 | Skeleton, tool check | done |
| 1 | Discovery | done: 19 sources, run on real data |
| 2 | Mail blocking | done: real-mail copy matches Gmail spam 9/9, 0 false positives |
| 3 | Removal workflow | done: lab + real plan; actions waiting on sites |
| 4 | Monitor + scorecard | done: lab + two real runs; weekly timer ready |
| 5 | Internet cleanup | in progress |
| 6 | Desktop app (`native-app` branch) | G0-G3 done (window, Overview, To do, Found, Clean-up, Mail, Settings); G4 reports + notifications next |
