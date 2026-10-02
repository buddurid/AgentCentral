import difflib
import json
import os
import mimetypes
import re
import shutil
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File as UploadFileParam, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from .db import DATA_DIR, Challenge, Entry, File, get_db, init_db
from .validator import validate_finding

ENTRY_TYPES = {"finding", "dead_end", "unconfirmed"}
ENTRY_STATUSES = {"confirmed", "incomplete", "invalidated"}


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    os.makedirs(os.path.join(DATA_DIR, "challenges"), exist_ok=True)
    yield


app = FastAPI(title="CTFHub", version="1.0.0", lifespan=lifespan)


# ---------------------------------------------------------------- schemas


class ChallengeCreate(BaseModel):
    name: str
    description: str = ""
    id: str | None = None


class EntryCreate(BaseModel):
    type: str
    title: str
    content: str = ""
    author: str = ""
    client_host: str = ""
    file_ids: list[int] = []


class EntryUpdate(BaseModel):
    type: str | None = None
    title: str | None = None
    content: str | None = None
    author: str | None = None
    status: str | None = None
    file_ids: list[int] | None = None


# ---------------------------------------------------------------- helpers


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", "-", value)
    value = value.strip("-")
    return value or uuid.uuid4().hex[:8]


def normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def match_challenge(db: Session, name: str) -> tuple[Challenge | None, str | None, float]:
    target = normalize_name(name)
    if not target:
        return None, None, 0.0
    challenges = db.query(Challenge).all()
    for challenge in challenges:
        if challenge.id == name.strip().lower() or normalize_name(challenge.name) == target:
            return challenge, "exact", 1.0
    best, best_score = None, 0.0
    for challenge in challenges:
        score = difflib.SequenceMatcher(None, target, normalize_name(challenge.name)).ratio()
        if score > best_score:
            best, best_score = challenge, score
    if best is not None and best_score >= 0.8:
        return best, "fuzzy", round(best_score, 3)
    return None, None, 0.0


def parse_file_ids(raw: str) -> list[int]:
    try:
        return list(json.loads(raw or "[]"))
    except (ValueError, TypeError):
        return []


def entry_dict(entry: Entry, full: bool = True) -> dict:
    data = {
        "id": entry.id,
        "challenge_id": entry.challenge_id,
        "type": entry.type,
        "title": entry.title,
        "content": entry.content,
        "author": entry.author,
        "client_host": entry.client_host,
        "status": entry.status,
        "file_ids": parse_file_ids(entry.file_ids),
        "created_at": entry.created_at.isoformat(),
        "updated_at": entry.updated_at.isoformat(),
    }
    if not full:
        data.pop("file_ids", None)
    return data


def challenge_dict(challenge: Challenge, counts: dict | None = None) -> dict:
    data = {
        "id": challenge.id,
        "name": challenge.name,
        "description": challenge.description,
        "created_at": challenge.created_at.isoformat(),
        "updated_at": challenge.updated_at.isoformat(),
    }
    if counts is not None:
        data.update(counts)
    return data


def file_dict(file: File) -> dict:
    return {
        "id": file.id,
        "challenge_id": file.challenge_id,
        "filename": file.filename,
        "size": file.size,
        "mime_type": file.mime_type,
        "created_at": file.created_at.isoformat(),
    }


def get_challenge_or_404(db: Session, challenge_id: str) -> Challenge:
    challenge = db.get(Challenge, challenge_id)
    if challenge is None:
        raise HTTPException(status_code=404, detail="challenge not found")
    return challenge


def get_entry_or_404(db: Session, challenge_id: str, entry_id: int) -> Entry:
    entry = db.get(Entry, entry_id)
    if entry is None or entry.challenge_id != challenge_id:
        raise HTTPException(status_code=404, detail="entry not found")
    return entry


def get_file_or_404(db: Session, challenge_id: str, file_id: int) -> File:
    file = db.get(File, file_id)
    if file is None or file.challenge_id != challenge_id:
        raise HTTPException(status_code=404, detail="file not found")
    return file


def challenge_counts(db: Session, challenge_id: str) -> dict:
    rows = (
        db.query(Entry.type, func.count(Entry.id))
        .filter(Entry.challenge_id == challenge_id)
        .group_by(Entry.type)
        .all()
    )
    by_type = {t: c for t, c in rows}
    files = (
        db.query(func.count(File.id)).filter(File.challenge_id == challenge_id).scalar()
    )
    return {
        "findings": by_type.get("finding", 0),
        "unconfirmed": by_type.get("unconfirmed", 0),
        "dead_ends": by_type.get("dead_end", 0),
        "files": files or 0,
    }


def validate_type_status(entry_type: str, status: str | None) -> str:
    if entry_type not in ENTRY_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"type must be one of {sorted(ENTRY_TYPES)}",
        )
    if status is not None and status not in ENTRY_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of {sorted(ENTRY_STATUSES)}",
        )
    if entry_type in ("finding", "dead_end"):
        return "confirmed"
    return status or "incomplete"


# ---------------------------------------------------------------- challenges


@app.post("/api/challenges", status_code=201)
def create_challenge(payload: ChallengeCreate, db: Session = Depends(get_db)):
    challenge_id = slugify(payload.id) if payload.id else slugify(payload.name)
    if db.get(Challenge, challenge_id):
        raise HTTPException(status_code=409, detail="challenge already exists")
    challenge = Challenge(
        id=challenge_id, name=payload.name, description=payload.description
    )
    db.add(challenge)
    db.commit()
    db.refresh(challenge)
    return challenge_dict(challenge, challenge_counts(db, challenge.id))


@app.get("/api/challenges")
def list_challenges(db: Session = Depends(get_db)):
    challenges = db.query(Challenge).order_by(Challenge.created_at).all()
    return [challenge_dict(c, challenge_counts(db, c.id)) for c in challenges]


@app.get("/api/challenges/resolve")
def resolve_challenge(name: str = Query(min_length=1), db: Session = Depends(get_db)):
    challenge, match, score = match_challenge(db, name)
    return {
        "challenge": challenge_dict(challenge, challenge_counts(db, challenge.id))
        if challenge
        else None,
        "match": match,
        "score": score,
    }


@app.get("/api/challenges/{challenge_id}")
def get_challenge(challenge_id: str, db: Session = Depends(get_db)):
    challenge = get_challenge_or_404(db, challenge_id)
    return challenge_dict(challenge, challenge_counts(db, challenge.id))


@app.delete("/api/challenges/{challenge_id}", status_code=204)
def delete_challenge(challenge_id: str, db: Session = Depends(get_db)):
    challenge = get_challenge_or_404(db, challenge_id)
    db.query(Entry).filter(Entry.challenge_id == challenge_id).delete()
    db.query(File).filter(File.challenge_id == challenge_id).delete()
    db.delete(challenge)
    db.commit()
    shutil.rmtree(os.path.join(DATA_DIR, "challenges", challenge_id), ignore_errors=True)


# ---------------------------------------------------------------- entries


def guard_finding(
    db: Session,
    challenge: Challenge,
    candidate: dict,
    exclude_entry_id: int | None = None,
):
    """Check a candidate finding against the challenge's other findings.

    Raises 422 with the validator's category, reason and the id of the finding
    it duplicates if the knowledge is already there. Validation is fail-open, so
    this only raises on an actual rejection.
    """
    query = db.query(Entry).filter(
        Entry.challenge_id == challenge.id, Entry.type == "finding"
    )
    if exclude_entry_id is not None:
        query = query.filter(Entry.id != exclude_entry_id)
    existing = [
        {"id": e.id, "type": e.type, "title": e.title, "content": e.content}
        for e in query.order_by(Entry.created_at.desc()).all()
    ]
    verdict = validate_finding({**candidate, "challenge": challenge.name}, existing)
    if not verdict.ok:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "finding rejected by validator",
                "category": verdict.category,
                "reason": verdict.reason,
                "duplicate_of": verdict.duplicate_of,
            },
        )


@app.post("/api/challenges/{challenge_id}/entries", status_code=201)
def create_entry(
    challenge_id: str, payload: EntryCreate, db: Session = Depends(get_db)
):
    challenge = get_challenge_or_404(db, challenge_id)
    status = validate_type_status(payload.type, None)
    if payload.type == "finding":
        guard_finding(
            db,
            challenge,
            {
                "title": payload.title,
                "content": payload.content,
                "author": payload.author,
            },
        )
    entry = Entry(
        challenge_id=challenge_id,
        type=payload.type,
        title=payload.title,
        content=payload.content,
        author=payload.author,
        client_host=payload.client_host,
        status=status,
        file_ids=json.dumps(payload.file_ids),
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry_dict(entry)


@app.get("/api/challenges/{challenge_id}/entries")
def list_entries(
    challenge_id: str,
    type: str | None = Query(default=None),
    status: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    get_challenge_or_404(db, challenge_id)
    query = db.query(Entry).filter(Entry.challenge_id == challenge_id)
    if type:
        query = query.filter(Entry.type == type)
    if status:
        query = query.filter(Entry.status == status)
    entries = query.order_by(Entry.created_at.desc()).all()
    return [entry_dict(e) for e in entries]


@app.get("/api/challenges/{challenge_id}/entries/{entry_id}")
def get_entry(challenge_id: str, entry_id: int, db: Session = Depends(get_db)):
    return entry_dict(get_entry_or_404(db, challenge_id, entry_id))


@app.put("/api/challenges/{challenge_id}/entries/{entry_id}")
def update_entry(
    challenge_id: str,
    entry_id: int,
    payload: EntryUpdate,
    db: Session = Depends(get_db),
):
    entry = get_entry_or_404(db, challenge_id, entry_id)
    new_type = payload.type or entry.type
    status = payload.status if payload.status is not None else entry.status
    validate_type_status(new_type, status)
    new_title = payload.title if payload.title is not None else entry.title
    new_content = payload.content if payload.content is not None else entry.content
    text_changed = (new_title, new_content) != (entry.title, entry.content)
    # Editing an entry into (or within) a finding is validated like a new finding
    if new_type == "finding" and (entry.type != "finding" or text_changed):
        guard_finding(
            db,
            get_challenge_or_404(db, challenge_id),
            {"title": new_title, "content": new_content, "author": entry.author},
            exclude_entry_id=entry.id,
        )
    entry.type = new_type
    if new_type in ("finding", "dead_end"):
        entry.status = "confirmed"
    else:
        entry.status = status
    entry.title = new_title
    entry.content = new_content
    if payload.author is not None:
        entry.author = payload.author
    if payload.file_ids is not None:
        entry.file_ids = json.dumps(payload.file_ids)
    db.commit()
    db.refresh(entry)
    return entry_dict(entry)


@app.delete("/api/challenges/{challenge_id}/entries/{entry_id}", status_code=204)
def delete_entry(challenge_id: str, entry_id: int, db: Session = Depends(get_db)):
    entry = get_entry_or_404(db, challenge_id, entry_id)
    db.delete(entry)
    db.commit()


@app.post("/api/entries/{entry_id}/confirm")
def confirm_entry(entry_id: int, db: Session = Depends(get_db)):
    entry = db.get(Entry, entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="entry not found")
    # Validate as finding before promoting
    guard_finding(
        db,
        get_challenge_or_404(db, entry.challenge_id),
        {"title": entry.title, "content": entry.content, "author": entry.author},
        exclude_entry_id=entry.id,
    )
    entry.type = "finding"
    entry.status = "confirmed"
    db.commit()
    db.refresh(entry)
    return entry_dict(entry)


@app.post("/api/entries/{entry_id}/invalidate")
def invalidate_entry(entry_id: int, db: Session = Depends(get_db)):
    entry = db.get(Entry, entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="entry not found")
    if entry.type != "unconfirmed":
        raise HTTPException(
            status_code=400, detail="only unconfirmed entries can be invalidated"
        )
    entry.status = "invalidated"
    db.commit()
    db.refresh(entry)
    return entry_dict(entry)


# ---------------------------------------------------------------- search


@app.get("/api/challenges/{challenge_id}/search")
def search_entries(
    challenge_id: str, q: str = Query(min_length=1), db: Session = Depends(get_db)
):
    get_challenge_or_404(db, challenge_id)
    like = f"%{q}%"
    entries = (
        db.query(Entry)
        .filter(
            Entry.challenge_id == challenge_id,
            or_(
                Entry.title.ilike(like),
                Entry.content.ilike(like),
                Entry.author.ilike(like),
            ),
        )
        .order_by(Entry.created_at.desc())
        .all()
    )
    return [entry_dict(e) for e in entries]


# ---------------------------------------------------------------- context


@app.get("/api/challenges/{challenge_id}/context")
def challenge_context(challenge_id: str, db: Session = Depends(get_db)):
    challenge = get_challenge_or_404(db, challenge_id)

    def entries_of(entry_type: str) -> list[dict]:
        rows = (
            db.query(Entry)
            .filter(Entry.challenge_id == challenge_id, Entry.type == entry_type)
            .order_by(Entry.created_at.desc())
            .all()
        )
        return [entry_dict(e, full=False) for e in rows]

    files = (
        db.query(File)
        .filter(File.challenge_id == challenge_id)
        .order_by(File.created_at.desc())
        .all()
    )
    return {
        "challenge": {"id": challenge.id, "name": challenge.name},
        "findings": entries_of("finding"),
        "unconfirmed": entries_of("unconfirmed"),
        "dead_ends": entries_of("dead_end"),
        "files": [{"id": f.id, "filename": f.filename} for f in files],
    }


# ---------------------------------------------------------------- files


@app.get("/api/challenges/{challenge_id}/files")
def list_files(challenge_id: str, db: Session = Depends(get_db)):
    get_challenge_or_404(db, challenge_id)
    files = (
        db.query(File)
        .filter(File.challenge_id == challenge_id)
        .order_by(File.created_at.desc())
        .all()
    )
    return [file_dict(f) for f in files]


@app.post("/api/challenges/{challenge_id}/files", status_code=201)
async def upload_file(
    challenge_id: str,
    file: UploadFile = UploadFileParam(...),
    db: Session = Depends(get_db),
):
    get_challenge_or_404(db, challenge_id)
    folder = os.path.join(DATA_DIR, "challenges", challenge_id, "files")
    os.makedirs(folder, exist_ok=True)
    original = os.path.basename(file.filename or "file")
    stored = f"{uuid.uuid4().hex}_{original}"
    path = os.path.join(folder, stored)
    size = 0
    with open(path, "wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            out.write(chunk)
    mime = file.content_type or mimetypes.guess_type(original)[0]
    record = File(
        challenge_id=challenge_id,
        filename=original,
        path=path,
        size=size,
        mime_type=mime or "application/octet-stream",
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return file_dict(record)


@app.get("/api/challenges/{challenge_id}/files/{file_id}")
def download_file(challenge_id: str, file_id: int, db: Session = Depends(get_db)):
    record = get_file_or_404(db, challenge_id, file_id)
    if not os.path.exists(record.path):
        raise HTTPException(status_code=404, detail="file missing on disk")
    return FileResponse(
        record.path, filename=record.filename, media_type=record.mime_type
    )


@app.delete("/api/challenges/{challenge_id}/files/{file_id}", status_code=204)
def delete_file(challenge_id: str, file_id: int, db: Session = Depends(get_db)):
    record = get_file_or_404(db, challenge_id, file_id)
    if os.path.exists(record.path):
        os.remove(record.path)
    db.delete(record)
    db.commit()


# ---------------------------------------------------------------- ui


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(os.path.dirname(__file__), "..", "static", "index.html"))
