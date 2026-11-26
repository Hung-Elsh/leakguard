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
.venv/bin/leakguard expand -p lab        # 5 candidates
.venv/bin/leakguard identities -p lab
.venv/bin/leakguard claim 3 4 5 7 -p lab && .venv/bin/leakguard reject 6 -p lab
.venv/bin/leakguard scan -p lab          # finds the backup email as a new candidate
.venv/bin/leakguard report -p lab
```
