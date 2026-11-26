"""Mock OSINT service for the lab (no internet). Mimics the response shapes of the real APIs
LeakGuard uses, serving fake exposures from data/seed.json.

Run:  .venv/bin/python lab/mock_osint/app.py        (binds 127.0.0.1:5055 only)
Reset removals:  rm lab/mock_osint/state.json
"""

from __future__ import annotations

import hashlib
import html
import json
import re
import uuid
from pathlib import Path

from flask import Flask, Response, abort, jsonify, request

HERE = Path(__file__).parent
SEED = json.loads((HERE / "data" / "seed.json").read_text())
STATE_FILE = HERE / "state.json"          # removals done through the mock opt-out form

app = Flask(__name__)
_intelx_searches: dict[str, str] = {}


def state() -> dict:
    return json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {"broker_removed": []}


def save_state(s: dict) -> None:
    STATE_FILE.write_text(json.dumps(s, indent=2))


def need_key(header: str) -> None:
    if not request.headers.get(header):
        abort(401)


def _term(q: str) -> str:
    """First quoted phrase of a search query, else the whole query (operators dropped)."""
    m = re.search(r'"([^"]+)"', q)
    return (m.group(1) if m else re.sub(r"\b(site|intext):\S+|\bOR\b", "", q)).strip().lower()


# ---- Have I Been Pwned v3 ------------------------------------------------------
@app.get("/hibp/api/v3/breachedaccount/<path:account>")
def hibp_breaches(account):
    need_key("hibp-api-key")
    rows = SEED["hibp_breaches"].get(account.lower())
    return jsonify(rows) if rows else ("", 404)


@app.get("/hibp/api/v3/pasteaccount/<path:account>")
def hibp_pastes(account):
    need_key("hibp-api-key")
    rows = SEED["hibp_pastes"].get(account.lower())
    return jsonify(rows) if rows else ("", 404)


# ---- IntelligenceX ---------------------------------------------------------------
@app.post("/intelx/intelligent/search")
def intelx_search():
    need_key("x-key")
    sid = str(uuid.uuid4())
    _intelx_searches[sid] = (request.get_json() or {}).get("term", "").lower()
    return jsonify({"id": sid, "status": 0})


@app.get("/intelx/intelligent/search/result")
def intelx_result():
    need_key("x-key")
    term = _intelx_searches.pop(request.args.get("id", ""), None)
    if term is None:
        return jsonify({"records": [], "status": 2})
    return jsonify({"records": SEED["intelx"].get(term, []), "status": 1})


@app.get("/intelx/intelligent/search/terminate")
def intelx_terminate():
    return ("", 204)


# ---- Google Programmable Search -------------------------------------------------
@app.get("/customsearch/v1")
def pse():
    if not request.args.get("key") or not request.args.get("cx"):
        abort(400)
    term = _term(request.args.get("q", ""))
    start = int(request.args.get("start", 1))
    removed = {f"/broker/person/{i}" for i in state()["broker_removed"]}
    items = [it for it in SEED["search"]
             if term in f"{it['title']} {it['snippet']} {it['link']}".lower()
             and not any(it["link"].endswith(r) for r in removed)]
    page = items[start - 1:start + 9]
    return jsonify({"items": page} if page else {})


# ---- Brave Search API ------------------------------------------------------------------
@app.get("/brave/res/v1/web/search")
def brave():
    if not request.headers.get("X-Subscription-Token"):
        return jsonify({"type": "ErrorResponse", "error": {"code": "SUBSCRIPTION_TOKEN_INVALID"}}), 401
    term = _term(request.args.get("q", ""))
    offset, count = int(request.args.get("offset", 0)), int(request.args.get("count", 20))
    removed = {f"/broker/person/{i}" for i in state()["broker_removed"]}
    items = [{"title": f"<strong>{html.escape(it['title'])}</strong>", "url": it["link"], "description": it["snippet"]}
             for it in SEED["search"] if term in f"{it['title']} {it['snippet']} {it['link']}".lower()
             and not any(it["link"].endswith(r) for r in removed)]
    page = items[offset * count:(offset + 1) * count]
    return jsonify({"type": "search", "query": {"original": request.args.get("q"),
                    "more_results_available": len(items) > (offset + 1) * count}, "web": {"results": page}})


# ---- LeakCheck public API ----------------------------------------------------------
@app.get("/leakcheck/api/public")
def leakcheck():
    hit = SEED["leakcheck"].get(request.args.get("check", "").lower())
    if not hit:
        return jsonify({"success": False, "error": "Not found"})
    return jsonify({"success": True, "found": len(hit["sources"]), **hit})


# ---- psbdmp ---------------------------------------------------------------------------
@app.get("/psbdmp/api/v3/search/<path:term>")
def psbdmp(term):
    return jsonify(SEED["psbdmp"].get(term.lower(), []))


# ---- Gravatar v3 ----------------------------------------------------------------------
@app.get("/gravatar/v3/profiles/<h>")
def gravatar(h):
    for email, prof in SEED["gravatar"].items():
        if hashlib.sha256(email.encode()).hexdigest() == h:
            return jsonify(prof)
    return jsonify({"error": "Profile not found"}), 404


# ---- Keyservers -----------------------------------------------------------------------
@app.get("/vks/v1/by-email/<path:email>")
def openpgp(email):
    key = SEED["pgp_openpgp"].get(email.lower())
    return Response(key, mimetype="application/pgp-keys") if key else ("Not found", 404)


@app.get("/pks/lookup")
def ubuntu_keyserver():
    key = SEED["pgp_ubuntu"].get(request.args.get("search", "").lower())
    return Response(key, mimetype="text/plain") if key else ("No results found", 404)


# ---- GitHub REST search -------------------------------------------------------------
@app.get("/github/search/commits")
def gh_commits():
    q = request.args.get("q", "")
    email = q.split("author-email:", 1)[-1].strip().lower()
    items = SEED["github_commits"].get(email, [])
    return jsonify({"total_count": len(items), "incomplete_results": False, "items": items})


@app.get("/github/search/users")
def gh_users():
    term = request.args.get("q", "").split(" in:", 1)[0].strip().lower()
    items = [{"login": u, "html_url": f"http://127.0.0.1:5055/github-web/{u}"}
             for u in SEED["github_users"] if term in u.lower()]
    return jsonify({"total_count": len(items), "items": items})


@app.get("/github/search/code")
def gh_code():
    return jsonify({"total_count": 0, "items": []})


# ---- Data broker (HTML, like the real ones) -----------------------------------------
def _broker_records():
    removed = set(state()["broker_removed"])
    return [r for r in SEED["broker_records"] if r["id"] not in removed]


@app.get("/broker/search")
def broker_search():
    q = request.args.get("q", "").lower()
    hits = [r for r in _broker_records() if q and any(q in str(v).lower() for v in r.values())]
    rows = "".join(
        f"<li><a href='/broker/person/{r['id']}'>{html.escape(r['name'])}</a> - {html.escape(r['city'])} - "
        f"{html.escape(r['email'])} - {html.escape(r['username'])}</li>" for r in hits)
    return f"<html><body><h1>PeopleFinder</h1><ul>{rows or '<li>No records found</li>'}</ul>" \
           f"<p><a href='/broker/optout'>Opt out</a></p></body></html>"


@app.get("/broker/person/<int:pid>")
def broker_person(pid):
    rec = next((r for r in _broker_records() if r["id"] == pid), None)
    if not rec:
        abort(404)
    return "<html><body>" + "".join(f"<p>{k}: {html.escape(str(v))}</p>" for k, v in rec.items()) + "</body></html>"


@app.route("/broker/optout", methods=["GET", "POST"])
def broker_optout():
    if request.method == "GET":
        return ("<html><body><h1>Opt out</h1><form method='post'>"
                "<input name='email' placeholder='email on the record'>"
                "<input name='record_url' placeholder='record URL'>"
                "<button type='submit'>Remove my record</button></form></body></html>")
    email = request.form.get("email", "").lower()
    s = state()
    hits = [r["id"] for r in SEED["broker_records"] if r["email"].lower() == email]
    s["broker_removed"] = sorted(set(s["broker_removed"]) | set(hits))
    save_state(s)
    return f"<html><body><p>Request received. {len(hits)} record(s) scheduled for removal.</p></body></html>"


# ---- Plain pages referenced by search results ---------------------------------------
@app.get("/paste/<pid>")
def paste_page(pid):
    for p in SEED["psbdmp"]["zorblat"]:
        if p["id"] == pid:
            return Response(p["text"], mimetype="text/plain")
    abort(404)


@app.get("/forum/u/<user>")
def forum_profile(user):
    return f"<html><body><h1>{html.escape(user)}</h1><p>Contact: zorblat.old@seclab.test</p></body></html>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5055, debug=False)
