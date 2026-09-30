import os
import tempfile

os.environ["HUB_DATA_DIR"] = tempfile.mkdtemp(prefix="hub-test-")
os.environ["HUB_VALIDATE"] = "0"

from fastapi.testclient import TestClient

from app.db import init_db
from app.main import app

init_db()
client = TestClient(app)


def make_challenge(cid: str) -> str:
    res = client.post("/api/challenges", json={"name": cid})
    if res.status_code == 409:
        return cid
    assert res.status_code == 201, res.text
    return res.json()["id"]


def make_entry(cid: str, type_: str, title: str, author: str = "agent-a") -> dict:
    res = client.post(
        f"/api/challenges/{cid}/entries",
        json={"type": type_, "title": title, "content": title + " body", "author": author},
    )
    assert res.status_code == 201, res.text
    return res.json()


def test_create_challenge():
    res = client.post("/api/challenges", json={"name": "web-admin", "description": "web"})
    assert res.status_code == 201
    assert res.json()["id"] == "web-admin"
    assert client.get("/api/challenges/web-admin").json()["name"] == "web-admin"


def test_create_finding():
    cid = make_challenge("t-finding")
    entry = make_entry(cid, "finding", "pickle.loads reachable")
    assert entry["type"] == "finding"
    assert entry["status"] == "confirmed"


def test_create_dead_end():
    cid = make_challenge("t-deadend")
    entry = make_entry(cid, "dead_end", "SQL injection in /api/users")
    assert entry["type"] == "dead_end"
    assert entry["status"] == "confirmed"


def test_create_unconfirmed():
    cid = make_challenge("t-unconfirmed")
    entry = make_entry(cid, "unconfirmed", "Possible command injection")
    assert entry["type"] == "unconfirmed"
    assert entry["status"] == "incomplete"


def test_invalidate_unconfirmed_keeps_it():
    cid = make_challenge("t-invalidate")
    entry = make_entry(cid, "unconfirmed", "Maybe SSRF")
    res = client.post(f"/api/entries/{entry['id']}/invalidate")
    assert res.status_code == 200
    assert res.json()["status"] == "invalidated"
    still_there = client.get(f"/api/challenges/{cid}/entries/{entry['id']}")
    assert still_there.status_code == 200
    assert still_there.json()["status"] == "invalidated"


def test_promote_unconfirmed_to_finding():
    cid = make_challenge("t-promote")
    entry = make_entry(cid, "unconfirmed", "Possible RCE")
    res = client.post(f"/api/entries/{entry['id']}/confirm")
    assert res.status_code == 200
    body = res.json()
    assert body["type"] == "finding"
    assert body["status"] == "confirmed"


def test_search():
    cid = make_challenge("t-search")
    make_entry(cid, "finding", "pickle deserialization")
    make_entry(cid, "finding", "unrelated note")
    res = client.get(f"/api/challenges/{cid}/search", params={"q": "pickle"})
    assert res.status_code == 200
    titles = [e["title"] for e in res.json()]
    assert titles == ["pickle deserialization"]


def test_upload_and_download_file():
    cid = make_challenge("t-files")
    res = client.post(
        f"/api/challenges/{cid}/files",
        files={"file": ("exploit.py", b"print('pwn')\n", "text/x-python")},
    )
    assert res.status_code == 201, res.text
    fid = res.json()["id"]
    assert res.json()["filename"] == "exploit.py"
    downloaded = client.get(f"/api/challenges/{cid}/files/{fid}")
    assert downloaded.status_code == 200
    assert downloaded.content == b"print('pwn')\n"


def test_challenge_isolation():
    a = make_challenge("iso-a")
    b = make_challenge("iso-b")
    make_entry(a, "finding", "libc leak in iso-a")
    client.post(
        f"/api/challenges/{a}/files",
        files={"file": ("secret.txt", b"a-only", "text/plain")},
    )

    context_b = client.get(f"/api/challenges/{b}/context").json()
    assert context_b["findings"] == []
    assert context_b["files"] == []

    search_b = client.get(f"/api/challenges/{b}/search", params={"q": "libc"}).json()
    assert search_b == []

    assert client.get(f"/api/challenges/{b}/files").json() == []


def test_context_shape_and_order():
    cid = make_challenge("t-context")
    make_entry(cid, "finding", "first finding")
    make_entry(cid, "unconfirmed", "hunch")
    make_entry(cid, "dead_end", "tried X")
    context = client.get(f"/api/challenges/{cid}/context").json()
    assert context["challenge"]["id"] == cid
    assert [e["title"] for e in context["findings"]] == ["first finding"]
    assert [e["title"] for e in context["unconfirmed"]] == ["hunch"]
    assert [e["title"] for e in context["dead_ends"]] == ["tried X"]


def test_resolve_existing_challenge_exact():
    cid = make_challenge("resolve-exact")
    body = client.get("/api/challenges/resolve", params={"name": cid}).json()
    assert body["match"] == "exact"
    assert body["challenge"]["id"] == cid


def test_resolve_challenge_tolerates_typo():
    cid = make_challenge("typo-target")
    body = client.get("/api/challenges/resolve", params={"name": "typo-targt"}).json()
    assert body["match"] == "fuzzy"
    assert body["challenge"]["id"] == cid


def test_resolve_unknown_returns_null():
    body = client.get(
        "/api/challenges/resolve", params={"name": "zzz-nothing-similar-zzz"}
    ).json()
    assert body["challenge"] is None
    assert body["match"] is None


def test_entry_records_client_host():
    cid = make_challenge("t-host")
    res = client.post(
        f"/api/challenges/{cid}/entries",
        json={
            "type": "finding",
            "title": "from a host",
            "content": "body",
            "author": "agent-a",
            "client_host": "ctf-box-01",
        },
    )
    assert res.status_code == 201, res.text
    assert res.json()["client_host"] == "ctf-box-01"

    context = client.get(f"/api/challenges/{cid}/context").json()
    assert context["findings"][0]["client_host"] == "ctf-box-01"


def test_entry_client_host_defaults_empty():
    cid = make_challenge("t-host-empty")
    assert make_entry(cid, "finding", "no host")["client_host"] == ""


def test_finding_rejected_by_validator(monkeypatch):
    from app import main
    from app.validator import Verdict

    cid = make_challenge("t-validator")
    monkeypatch.setattr(
        main,
        "validate_finding",
        lambda candidate, existing: Verdict(
            ok=False, category="duplicate", reason="already known"
        ),
    )
    res = client.post(
        f"/api/challenges/{cid}/entries",
        json={"type": "finding", "title": "dup", "content": "x", "author": "a"},
    )
    assert res.status_code == 422
    assert res.json()["detail"]["category"] == "duplicate"

    # nothing was persisted
    assert client.get(f"/api/challenges/{cid}/entries").json() == []


def test_confirm_rejected_by_validator(monkeypatch):
    from app import main
    from app.validator import Verdict

    cid = make_challenge("t-validator-confirm")
    entry = make_entry(cid, "unconfirmed", "hunch")
    monkeypatch.setattr(
        main,
        "validate_finding",
        lambda candidate, existing: Verdict(
            ok=False, category="erroneous", reason="unproven"
        ),
    )
    res = client.post(f"/api/entries/{entry['id']}/confirm")
    assert res.status_code == 422
    assert res.json()["detail"]["category"] == "erroneous"

    # still unconfirmed, not promoted
    body = client.get(f"/api/challenges/{cid}/entries/{entry['id']}").json()
    assert body["type"] == "unconfirmed"
    assert body["status"] == "incomplete"


def test_update_into_finding_is_validated(monkeypatch):
    from app import main
    from app.validator import Verdict

    cid = make_challenge("t-validator-update")
    entry = make_entry(cid, "unconfirmed", "hunch")
    monkeypatch.setattr(
        main,
        "validate_finding",
        lambda candidate, existing: Verdict(
            ok=False, category="malformed", reason="not a note"
        ),
    )
    res = client.put(
        f"/api/challenges/{cid}/entries/{entry['id']}",
        json={"type": "finding", "title": "now a finding", "content": "body"},
    )
    assert res.status_code == 422
    assert res.json()["detail"]["category"] == "malformed"

    body = client.get(f"/api/challenges/{cid}/entries/{entry['id']}").json()
    assert body["type"] == "unconfirmed"
    assert body["title"] == "hunch"
