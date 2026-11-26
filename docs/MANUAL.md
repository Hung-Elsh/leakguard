# LeakGuard manual

How to use LeakGuard from first setup to verified removal. Every command takes `-p lab` (the fictional lab
identity, no internet) or `-p internet` (your real data). Examples use `-p internet` and placeholder values:
`yourkeyword`, `you@example.com`, `old.you@example.com`, `yourname42`.

1. [Setup](#1-setup)
2. [Your identity](#2-your-identity)
3. [Discovery](#3-discovery)
4. [Verdicts](#4-verdicts)
5. [Removal](#5-removal)
6. [Mail blocking](#6-mail-blocking)
7. [Monitoring and scorecard](#7-monitoring-and-scorecard)
8. [The lab](#8-the-lab)
9. [Troubleshooting](#9-troubleshooting)
10. [Data and privacy](#10-data-and-privacy)

---

## 1. Setup
```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[lab,browser,dev]'
cp .env.example .env && chmod 600 .env
python3 scripts/patch_ghunt.py
.venv/bin/leakguard init
.venv/bin/leakguard install-hook
.venv/bin/leakguard doctor -p internet
```
- **`.env` keys:** `HIBP_API_KEY` (paid, best breach data), `INTELX_API_KEY` (free tier), `BRAVE_API_KEY` (web
  search, free tier), `GITHUB_TOKEN` (optional: code search, higher limits). Sources without their key are skipped.
- **External tools** (holehe, Sherlock, Maigret, GHunt, Blackbird, Mosint, socialscan, h8mail, SpiderFoot):
  `doctor` lists what is missing and the exact install command. GHunt also needs `ghunt login` (use a
  secondary Google account) and `scripts/patch_ghunt.py` after every GHunt install or upgrade.
- **Gmail** (mail blocking and sending removal requests): create a Google Cloud OAuth client (Desktop app), add
  your address as a test user, save the JSON as `~/.config/leakguard/client_secret.json` (mode 600). The first
  Gmail command opens a browser to approve access; adding a permission later asks once more.

## 2. Your identity
LeakGuard only scans and cleans identities you have **claimed**. The keyword and the emails you enter with `init`
are claimed from the start. Scans propose more as **candidates** (old addresses, usernames).

```bash
leakguard identities -p internet                    # claimed / candidate / rejected, with IDs
leakguard claim 4 7 -p internet                     # by ID
leakguard claim old.you@example.com yourname42      # by value; a value not listed yet is added as yours
leakguard reject 9 someone-else -p internet         # not yours: never scanned or proposed again
```
- A value is matched exactly (case and a leading `@` are ignored). No exact match: `claim` adds it as yours,
  `reject` adds it as rejected.
- Claimed values are also saved in your private identity file; rejecting one you declared removes it there
  (your last remaining email cannot be removed: change it with `leakguard init`).

## 3. Discovery
```bash
leakguard scan -p internet                          # stage 1: keyword, stage 2: claimed identities
leakguard scan --stage keyword -p internet          # only search the keyword and propose candidates
leakguard scan --stage identities -s holehe -s ghunt -p internet   # only some sources
leakguard findings -p internet --status new         # what is new since last time
leakguard report -p internet                        # Markdown + JSON in ~/.local/share/leakguard/reports/
```
**Run results** (also stored for the dashboard):

| Status | Meaning |
|---|---|
| `ok` | The source answered fully |
| `partial` | Some sub-checks got no answer (e.g. holehe sites rate-limited). Earlier findings are never marked gone by a partial run. Re-run later to fill gaps |
| `skipped` | A precondition is missing (key, tool) or the source is disabled in `config/sources.json` |
| `error` | Full detail is logged: HTTP status, the service's reply or the tool's own output, timing. API keys are masked |
| `scope_blocked` | The request would have left the profile's allowed hosts |

**Severity** follows the evidence: high = a password/hash shown or a known credential compilation, or your email on
a public page; medium = a breach whose contents are unknown; low = an account or an exact name match; info =
search results that only look similar.

**Username false positives:** some sites say "exists" for any username. Sherlock and Maigret hits are re-checked
with a random username; sites that also "find" it are dropped (listed in the run log).

**Password check:** `leakguard password-check` asks for a password (not shown, not stored), hashes it locally and
sends only the first 5 characters of the hash to HIBP Pwned Passwords. "Found N times" means: change it everywhere.

## 4. Verdicts
Sources say what they see; **you** decide what it means. The verdict drives the removal plan.

| Verdict | Use for | Removal plan |
|---|---|---|
| `open` (default) | A real exposure to clean up | One removal action per site |
| `protect` | Your own account you keep (e.g. your main mailbox and accounts that reset through it) | One security checklist, never deletion |
| `accepted` | Known, no action needed (e.g. an address you will abandon) | Skipped |
| `false_positive` | Not you, or the source was wrong | Skipped |

```bash
leakguard findings -p internet --verdict open
leakguard mark 9c77f6f0 735af746 --as protect --note "main game account, linked to the mailbox" -p internet
leakguard mark e3491c0e --as false_positive --note "not my account" -p internet
```
IDs: the first 6+ characters are enough.

## 5. Removal
Five commands cover the whole workflow.

```bash
leakguard remove status -p internet                 # refresh the plan, list actions
leakguard remove status 5 -p internet               # one action: steps, contact, findings, history
leakguard remove do 5 -p internet                   # perform it (preview for email/form)
leakguard remove do 5 --confirm -p internet         # send the email / submit the form
leakguard remove set 5 done --note "deleted it" -p internet
leakguard remove check -p internet                  # re-scan everything waiting on a site
```

**How the plan is built** (`remove status` refreshes it every time):
- One action per target: the same account found by several tools is one action with all the evidence.
- Breached site: delete your account there (GDPR-style request where an address is known).
- Credential compilations: one "change those passwords" action. Leak indexes (IntelX): one removal request.
  Pastes: one report per paste site. Brokers: opt-out. Every breached address: HIBP opt-out.
- Contacts come from a hand-checked catalog, then the JustDeleteMe dataset (downloaded automatically, refreshed
  every 30 days). Anything else is **unverified** and will not be sent until you set a contact you checked.

**What `do` does by method:**

| Method | `remove do ID` | `remove do ID --confirm` |
|---|---|---|
| email | Writes and shows the request (from your address) | Sends it (lab: Mailpit; internet: your Gmail). Refused without a verified address |
| form | Fills the opt-out form in a headless browser, saves a screenshot | Submits it, screenshots the result |
| manual / checklist | Shows the steps and link | (nothing to send: you do it, then `remove set ID done`) |

**Recording progress with `set`:**
```bash
leakguard remove set 9 --contact https://site.example/abuse -p internet      # a contact you checked
leakguard remove set 9 requested --note "sent via their form" -p internet    # schedules a follow-up
leakguard remove set 9 acknowledged --note "they replied: queued" -p internet
leakguard remove set 6 skipped --note "site no longer exists" -p internet
leakguard remove set 3 done --note "deleted it myself" -p internet
```
States: planned → drafted → requested → acknowledged → removed → **verified**, plus `done` (manual steps,
checklists) and `skipped`. Impossible jumps are refused; every change is kept in the action's history.

**Verification:** `remove check` re-runs only the sources behind an action, for only its identities. An action is
`verified` only when every linked finding is gone. Checklists, password changes and the HIBP opt-out are confirmed
by you (`set ID done`): their evidence (breach records) never disappears.

**Accounts no scan found** (e.g. you know from an old mail):
```bash
leakguard remove add "Some Site" -i you@example.com --why "password-reset mail 2024-07" -p internet
```

**Practical cases**
- *Forgot the password:* use the site's own "Forgot password": the reset goes to the registered address. Find
  that address by searching your mailbox for the site's welcome mail, and check
  myaccount.google.com/connections ("Sign in with Google" accounts need no site password). If the address is one
  you can no longer read, ask the site's support for deletion.
- *Only a contact form, no address:* `remove do ID` still writes the request; paste it into the form, then
  `remove set ID requested --note "via contact form"`.
- *The site is gone* (parked or expired domain): `remove set ID skipped --note "site defunct"`.
- *Leak indexes:* removing records is not the same as deleting your account there. Use their removal/abuse page.

## 6. Mail blocking
```bash
leakguard block -p internet                         # dry run: what would be blocked, and why
leakguard block --apply -p internet                 # move it: Junk, Trash, LeakGuard/Review (nothing deleted)
leakguard block --apply --filters -p internet       # also sync your blocklist to Gmail server-side filters
```
- Rules: `config/block_rules.json` (sextortion, phishing, failed SPF/DMARC, scams, machine-generated domains,
  mass BCC, newsletters first seen after the leak).
- Your lists: `~/.config/leakguard/mail_rules.yaml` (`allow`, `block`, `leak_date`), created on the first run. The
  allowlist always wins. People you have written to count as known and are never caught by generic rules.
- Test on a copy of your real mail in the lab first:
  ```bash
  leakguard lab-import ~/.local/share/leakguard/takeout/<export>.mbox
  leakguard block -p lab --owner-copy --since 0 --limit 2000   # compared with Gmail's own Spam label
  ```

## 7. Monitoring and scorecard
```bash
leakguard monitor -p internet                       # full check-up now
leakguard monitor --quick -p internet               # skip the slow tools (Maigret, SpiderFoot, Sherlock, Blackbird)
leakguard monitor --mail -p internet                # also email the alert to your own address
leakguard monitor --schedule weekly -p internet     # write a systemd timer; prints the commands to enable it
```
One run: full scan (keyword, then claimed identities) → re-check every removal whose follow-up is due → reopen any
removal whose data came back (the scorecard never keeps a removal that was undone) → diff against the previous
state → snapshot → report in `~/.local/share/leakguard/reports/<profile>-monitor-*.md` → alert.

- **What is reported:** new exposures (grouped: one line per page/record, with the sources and identities that
  saw it), items no longer seen, new candidates, removal changes, removals that came back, sources that failed
  (e.g. an expired GHunt login).
- **Alerts:** a desktop notification when there is something new from `--min-severity` (default medium) up, new
  candidates, verified or undone removals, or source errors. `--mail` also mails the report to your address.
- **Scorecard** (in every monitor report and in `leakguard report`): exposures found since the first scan, still
  open, no longer seen and how many of those were verified by a removal action, accounts deleted / in progress,
  protected accounts, removal actions by state, mail blocked in the last 7 days, and the trend over monitor runs.
- **Honest numbers:** breach records are permanent, so a run that does not return one (a flaky lookup service) never
  marks it gone; every run re-rates stored search results with the current rules, so an old rating cannot count as
  a removal; a removal whose data comes back is reopened.
- **Manual use is fine:** run `leakguard monitor -p internet` whenever you like (for example weekly, and after the
  follow-up dates shown by `leakguard remove status --due`). The timer below is optional.

**Final cleanup report:**
```bash
leakguard report --final -p internet            # readable report: found, done (with dates), waiting, scorecard
leakguard report --final --share -p internet    # the same with every identity masked, to share with others
```
`--share` masks your keyword, emails, usernames, name and Google IDs everywhere (also inside URLs), and refuses to
write the file if any private term is left. Both go to `~/.local/share/leakguard/reports/` (mode 600).

**Optional: run it automatically (systemd user timer).** `monitor --schedule daily|weekly|monthly` only writes two
files to `~/.local/share/leakguard/systemd/` (add `--quick` / `--mail` to bake those options in). Enable them:
```bash
mkdir -p ~/.config/systemd/user && cp ~/.local/share/leakguard/systemd/leakguard-monitor.* ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now leakguard-monitor.timer
systemctl --user list-timers leakguard-monitor.timer         # when it runs next
journalctl --user -u leakguard-monitor.service -n 50          # output of the last runs
sudo loginctl enable-linger $USER                             # optional: also run while logged out
```
It runs at 09:00 (weekly: Mondays) with up to 30 minutes of random delay, and catches up after the machine was off.
Without linger it only runs while you are logged in. To turn it off again:
```bash
systemctl --user disable --now leakguard-monitor.timer
rm ~/.config/systemd/user/leakguard-monitor.{service,timer} && systemctl --user daemon-reload
```

## 8. The lab
No internet: fake OSINT services on 127.0.0.1:5055, GreenMail/Mailpit on 192.168.1.250, recorded tool output for
the tools that only talk to real sites, and a fictional identity (`zorblat`). See [lab/README.md](../lab/README.md).

## 9. Troubleshooting
| Symptom | Cause / fix |
|---|---|
| GHunt crashes (`KeyError: 'container'`, JSON errors, `NameError: photos`) | Google changed its replies: `python3 scripts/patch_ghunt.py` |
| holehe/socialscan `partial` with many rate limits | Sites throttle by IP. Re-run later; findings accumulate and nothing is marked gone by a partial run |
| Blackbird `wmn-data.json` missing | Fixed automatically: it downloads its site list on the first username run |
| Gmail `quota exceeded` | Requests are paced and retried; if it persists, wait a minute |
| Gmail asks for consent again | A permission was added (e.g. sending requests). Approve once |
| A source `skipped: disabled` | Turned off in `config/sources.json` (e.g. Google Custom Search is closed to new projects; psbdmp is offline) |
| A site resolves to 127.0.0.1/::1 | A hosts-file or DNS blocklist on this machine |
| `leakcheck` fails before a commit | A file contains your private identity: remove it or git-ignore the file |

## 10. Data and privacy
- Your identity, Gmail token and mail lists live in `~/.config/leakguard/`; scans, reports, drafts, screenshots
  and raw tool output in `~/.local/share/leakguard/` (private permissions). None of it is in the repository.
- Leaked passwords are masked everywhere (findings, reports, drafts). API keys are masked in logs.
- The claim gate: only claimed identities are scanned or cleaned. Nothing is sent or submitted without
  `--confirm`, and mail blocking is a dry run until `--apply`.
- LeakGuard never logs in to third-party accounts with leaked or guessed passwords.
