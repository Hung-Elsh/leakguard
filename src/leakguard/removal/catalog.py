"""Where and how to remove the owner from a site: profile catalog > repo catalog > JustDeleteMe dataset."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from ..config import Settings
from ..paths import CONFIG, DATA, ROOT

JDM_URL = "https://raw.githubusercontent.com/jdm-contrib/jdm/master/_data/sites.json"
JDM_CACHE = DATA / "jdm_sites.json"


def site_key(name: str) -> str:
    """'GeeksforGeeks', 'Geeksfor Geeks', 'GeeksForGeeks' -> 'geeksforgeeks'."""
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


@dataclass
class Entry:
    key: str
    name: str
    method: str                  # email | form | manual
    verified: bool               # contact checked by hand (or owner-provided)
    origin: str                  # catalog file / jdm
    url: str = ""
    email: str = ""
    steps: str = ""
    form: dict | None = None
    domains: tuple[str, ...] = ()
    pinned: bool = False         # hand-checked procedure: JustDeleteMe must not override method/contact/steps


class Catalog:
    def __init__(self, settings: Settings):
        self.entries: dict[str, Entry] = {}
        self.by_domain: dict[str, str] = {}
        # Order matters: the hand-checked repo catalog first, then JustDeleteMe (community-maintained, so its links
        # are fresher and win; repo steps are kept when JDM has none), then the profile's own catalog (lab) on top.
        self._load(CONFIG / "removal_catalog.json", "catalog")
        jdm = (settings.removal.get("jdm") and ROOT / settings.removal["jdm"]) or JDM_CACHE
        self._load_jdm(Path(jdm))
        if settings.removal.get("catalog"):
            self._load(ROOT / settings.removal["catalog"], settings.profile)

    def _add(self, e: Entry) -> None:
        self.entries[e.key] = e
        for d in e.domains:
            self.by_domain[d.lower()] = e.key

    def _load(self, path: Path, origin: str) -> None:
        for key, d in json.loads(path.read_text()).get("sites", {}).items():
            self._add(Entry(key, d.get("name", key), d.get("method", "manual"), bool(d.get("verified")), origin,
                            d.get("url", ""), d.get("email", ""), d.get("steps", ""), d.get("form"),
                            tuple(d.get("domains", [])), bool(d.get("pinned"))))

    def _load_jdm(self, path: Path) -> None:
        if not path.exists():
            return
        for d in json.loads(path.read_text()):
            email = d.get("email") or ""
            method = "email" if email and not d.get("url") else "manual"
            key = site_key(d.get("name", ""))
            old = self.entries.get(key)
            if old and old.pinned:
                continue
            notes = d.get("notes") or (old.steps if old else "")          # JDM notes, else the hand-written steps
            steps = " ".join(x for x in (notes, f"(JustDeleteMe difficulty: {d['difficulty']})" if d.get("difficulty") else "") if x)
            self._add(Entry(key, d.get("name", ""), method, True, "justdeleteme", d.get("url", "") or (old.url if old else ""),
                            email or "", steps, old.form if old else None,
                            tuple(d.get("domains", [])) or (old.domains if old else ())))

    def lookup(self, name: str = "", domain: str = "") -> Entry | None:
        # the full name, then its words ("Envato Forum" -> "envato"), before any domain guess: a domain can be
        # claimed by the software a site runs on (forums.envato.com is listed under Discourse)
        words = [w for w in re.split(r"[\s._-]+", name or "") if len(w) >= 3]
        for k in [site_key(name)] + sorted({site_key(w) for w in words}, key=len, reverse=True):
            if k and k in self.entries:
                return self.entries[k]
        domain = (domain or "").lower().removeprefix("www.")
        while domain:
            if domain in self.by_domain:
                return self.entries[self.by_domain[domain]]
            domain = domain.partition(".")[2]
        return None
