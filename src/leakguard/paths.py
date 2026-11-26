"""Paths. Personal data never lives inside the repository:

- USER_CONFIG (~/.config/leakguard):        the owner's identity (created by `leakguard init`), OAuth tokens
- DATA        (~/.local/share/leakguard):   SQLite stores, raw tool output, reports
The repository holds only code, generic config and the fictional lab identity.
"""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config"
LAB_IDENTITY = ROOT / "lab" / "identities.yaml"

USER_CONFIG = Path(os.environ.get("LEAKGUARD_CONFIG", Path.home() / ".config" / "leakguard"))
USER_IDENTITY = USER_CONFIG / "identities.yaml"
USER_MAIL_RULES = USER_CONFIG / "mail_rules.yaml"      # allow/block lists, leak date
LAB_MAIL_RULES = ROOT / "lab" / "mail_rules.yaml"

DATA = Path(os.environ.get("LEAKGUARD_DATA", Path.home() / ".local" / "share" / "leakguard"))
REPORTS = DATA / "reports"
TAKEOUT = DATA / "takeout"          # Google Takeout exports (.mbox) for the lab copy
