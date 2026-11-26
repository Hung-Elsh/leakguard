"""Plan, act and verify. Verification = re-run the sources that found an action's findings; an action is
verified only when all of them are gone (a partial run never counts)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from .. import engine
from ..config import Settings
from ..scope import ScopeGuard
from ..store import Store
from . import browser, drafts, sender
from .catalog import Catalog, site_key
from .planner import build

FOLLOW_UP_DAYS = {"email": 30, "form": 7, "manual": 7}      # GDPR answers are due within a month
# Closed by the owner, never by a re-scan: their evidence (breach records) does not disappear.
OWNER_CONFIRMED = {"protect_checklist", "rotate_password", "hibp_optout"}


def plan(settings: Settings, store: Store) -> tuple[int, int]:
    """Create/merge actions. Returns (created, updated)."""
    created = updated = 0
    for p in build(store, Catalog(settings)):
        _, new = store.upsert_action(p.as_dict())
        created += new
        updated += not new
    return created, updated


def _due(method: str) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=FOLLOW_UP_DAYS.get(method, 7))).replace(microsecond=0).isoformat()


def draft(settings: Settings, store: Store, action_id: int):
    msg, path = drafts.render(settings, store, action_id)
    state = store.action(action_id)["state"]
    if state == "planned":
        store.set_action_state(action_id, "drafted", "draft written", draft_path=str(path))
    else:                                   # re-render: refresh the file, no new history entry
        store.db.execute("UPDATE actions SET draft_path=? WHERE id=?", (str(path), action_id))
        store.db.commit()
    return msg, path


def send(settings: Settings, store: Store, action_id: int, confirm: bool) -> str:
    a = store.action(action_id)
    if not a["contact_verified"]:
        raise drafts.DraftError(f"action {action_id}: contact {a['contact'] or '(none)'} is not verified; check it and "
                                "set it with `leakguard remove set ID --contact ...` first")
    msg, path = draft(settings, store, action_id)
    if not msg["To"]:
        raise drafts.DraftError(f"action {action_id}: no email address to send to (draft at {path} can be pasted "
                                "into the site's contact form instead)")
    if not confirm:
        return f"preview only (draft {path}); add --confirm to send"
    how = sender.send(settings, ScopeGuard(settings), msg)
    store.set_action_state(action_id, "requested", f"sent via {how} to {a['contact']}", next_check=_due("email"))
    return f"sent via {how}"


def submit_form(settings: Settings, store: Store, action_id: int, confirm: bool) -> browser.FormResult:
    a = store.action(action_id)
    entry = Catalog(settings).lookup(a["target"]) or Catalog(settings).entries.get(a["key"].split(":", 1)[1])
    if not entry or not entry.form:
        raise drafts.DraftError(f"action {action_id}: no form definition in the catalog for {a['target']}")
    findings = store.findings_by_ids(json.loads(a["finding_ids"] or "[]"))
    values = {"email": drafts.sender_address(settings), "url": next((f["url"] for f in findings if f["url"]), "")}
    res = browser.fill(settings, ScopeGuard(settings), action_id, entry.url, entry.form, values, confirm)
    if res.submitted:
        note = f"form submitted ({'success text seen' if res.success else 'no success text'}); screenshot {res.after}"
        store.set_action_state(action_id, "requested", note, next_check=_due("form"))
    return res


def check(settings: Settings, store: Store, action_id: int) -> str:
    """Re-run the linked sources; move the action to verified when every linked finding is gone."""
    a = store.action(action_id)
    if a["kind"] in OWNER_CONFIRMED:
        return f"{a['kind']}: confirmed by you with `leakguard remove set ID done`, not by a re-scan (state {a['state']})"
    findings = store.findings_by_ids(json.loads(a["finding_ids"] or "[]"))
    if not findings:
        return "no linked findings to re-check; close it with `leakguard remove set ID done` when you have done it"
    sources = sorted({f["source"] for f in findings})
    idents = {f["identity"] for f in findings}
    engine.rescan(settings, store, sources, idents)
    after = store.findings_by_ids([f["id"] for f in findings])
    gone = [f for f in after if f["status"] == "gone"]
    if len(gone) == len(after):
        if a["state"] in ("requested", "acknowledged", "removed", "done"):
            store.set_action_state(action_id, "verified", f"all {len(after)} linked finding(s) gone after re-check")
            return f"verified: all {len(after)} linked finding(s) are gone"
        return f"all {len(after)} linked finding(s) are gone, but no request was recorded (state {a['state']})"
    store.set_action_state(action_id, a["state"], f"re-check: {len(gone)}/{len(after)} gone", next_check=_due(a["method"]))
    still = ", ".join(sorted({f["source"] for f in after if f["status"] != "gone"}))
    return f"not yet: {len(gone)}/{len(after)} linked finding(s) gone (still seen by: {still})"


def entry_for(settings: Settings, a) -> object:
    return Catalog(settings).lookup(a["target"]) or Catalog(settings).entries.get(site_key(a["key"].split(":", 1)[-1]))
