"""`leakguard block`: fetch, classify, then (only with apply=True) move messages and sync filters."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ..config import Settings, read_identity
from ..paths import LAB_MAIL_RULES, USER_MAIL_RULES
from ..scope import ScopeGuard
from ..store import Store
from .backend import make_backend
from .importer import owner_copy_settings
from .message import SPAM_LABELS, MailMessage, gmail_labels
from .rules import Classifier, OwnerLists, Verdict

TEMPLATE = """# LeakGuard mail lists. Private: never copy into the repository.
# leak_date: senders first seen on/after this date are not "known" (YYYY-MM-DD, or leave empty).
leak_date:
allow:              # never touched, whatever the rules say
  addresses: []
  domains: []
block:              # always trashed; synced to Gmail filters with `leakguard block --filters --apply`
  addresses: []
  domains: []
"""


@dataclass
class BlockResult:
    total: int = 0
    rows: list[tuple[MailMessage, Verdict]] = field(default_factory=list)
    applied: dict[str, int] = field(default_factory=dict)
    filter_plan: list[str] = field(default_factory=list)
    gmail: dict[str, list[MailMessage]] = field(default_factory=dict)   # comparison with Gmail labels

    def counts(self) -> dict[str, int]:
        c: dict[str, int] = defaultdict(int)
        for _, v in self.rows:
            c[v.action] += 1
        return dict(c)


def rules_path(settings: Settings, private: bool = False):
    if settings.is_lab and not private:
        return LAB_MAIL_RULES
    if not USER_MAIL_RULES.exists():
        USER_MAIL_RULES.parent.mkdir(parents=True, exist_ok=True)
        USER_MAIL_RULES.write_text(TEMPLATE)
        USER_MAIL_RULES.chmod(0o600)
    return USER_MAIL_RULES


def owner_addresses(settings: Settings, store: Store) -> set[str]:
    me = {s["value"] for s in settings.seeds if s.get("kind") == "email"}
    me |= {i.value for i in store.identities("claimed") if i.kind == "email"}
    return me


def compare_with_gmail(rows: list[tuple[MailMessage, Verdict]]) -> dict[str, list[MailMessage]]:
    """For Takeout copies: X-Gmail-Labels tells what Gmail decided. 'label' (review) is not a block."""
    out: dict[str, list[MailMessage]] = {"both": [], "leakguard_only": [], "gmail_only": []}
    seen = False
    for m, v in rows:
        labels = gmail_labels(m.header("X-Gmail-Labels"))
        seen = seen or bool(labels)
        g, lg = bool(labels & SPAM_LABELS), v.action in ("spam", "trash")
        if g and lg:
            out["both"].append(m)
        elif lg:
            out["leakguard_only"].append(m)
        elif g:
            out["gmail_only"].append(m)
    return out if seen else {}


def run(settings: Settings, store: Store, folder: str = "INBOX", since_days: int | None = 90,
        limit: int = 500, apply: bool = False, filters: bool = False, owner_copy: bool = False) -> BlockResult:
    if owner_copy:
        # the lab copy of the owner's real mail: lab mailbox, but the owner's own identity and lists
        settings = owner_copy_settings(settings)
        me = set(read_identity("internet")["emails"])
        lists = OwnerLists.load(rules_path(settings, private=True), me)
    else:
        lists = OwnerLists.load(rules_path(settings), owner_addresses(settings, store))
    guard = ScopeGuard(settings)
    backend = make_backend(settings, guard)
    res = BlockResult()
    try:
        msgs = backend.fetch(folder, since_days, limit)
        res.total = len(msgs)
        lists.known |= backend.known_correspondents()
        clf = Classifier(lists)
        clf.learn_known(msgs)
        res.rows = [(m, clf.classify(m)) for m in msgs]
        res.gmail = compare_with_gmail(res.rows)
        by_action: dict[str, list[str]] = defaultdict(list)
        for m, v in res.rows:
            by_action[v.action].append(m.uid)
        if apply:
            for action, uids in by_action.items():
                res.applied[action] = backend.apply(action, uids)
        store.log_mail(settings.profile + ("-owner-copy" if owner_copy else ""), [(m.message_id, m.from_addr, m.subject, v.rule, v.action)
                                         for m, v in res.rows if v.action != "keep"], applied=apply)
        if filters and backend.supports_filters:
            res.filter_plan = backend.sync_filters(lists, apply)
    finally:
        backend.close()
    return res
