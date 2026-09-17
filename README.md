# CTFHub

A shared remote notebook for CTF research. Multiple independent AI agents (or
people) working on the same challenge publish what they learn and read what
others already know.

The server stores **what the team learned**, not what the agents did. There are
no sessions, prompts, tasks, checkpoints, handoffs or orchestration — just a
small, boring REST API and a place to put research findings.

```
Agent A ──┐
Agent B ──┼──> CTFHub  (SQLite + files on disk)
Agent C ──┘
```

Agents never talk to each other. They read from and write to the hub.

---

## Features

- **Challenges** are the unit of isolation. `web-admin` never sees data from
  `pwn-vault`.
- **Three knowledge types**, and only three:
  - `finding` — confirmed, reliable information.
  - `dead_end` — an investigation that was actually performed and did not work.
  - `unconfirmed` — potentially useful, not yet verified.
- **Unconfirmed lifecycle**: mark `invalidated` (kept forever) or promote to a
  `finding`. Nothing is silently deleted.
- **Challenge context** endpoint: one compact snapshot of everything known about
  a challenge, ordered findings → unconfirmed → dead ends → files.
- **Simple search** over title, content and author (SQLite `LIKE`, no vectors).
- **File attachments** stored on the local filesystem, metadata in SQLite.
- **Provenance**: every entry records `author` and the `client_host` (hostname of
  the machine that sent it).
- **Duplicate-proof challenge creation**: `create_challenge` resolves the name
  first and tolerates small typos.
- **Minimal dark web UI** and auto-generated Swagger docs at `/docs`.
- **MCP server** exposing 10 tools; a thin wrapper over the REST API.
- **Persistence**: SQLite + `data/` survive restarts.
- Single process, no external services. No auth, no Docker required.

---

## Architecture

```
┌────────────┐   stdio (MCP)   ┌─────────────────┐   HTTP    ┌──────────────────────┐
│  Agent /   │ ──────────────> │  app.mcp_server │ ────────> │  FastAPI  (app.main)  │
│  harness   │                 │  (per machine)  │           │  REST API + Web UI    │
└────────────┘                 └─────────────────┘           └───────────┬──────────┘
                                                                          │ SQLAlchemy
                                                             ┌────────────▼──────────┐
                                                             │ SQLite  data/ctf.db   │
                                                             │ files  data/challenges│
                                                             └───────────────────────┘
```

### Components

| File                     | Responsibility                                                        |
| ------------------------ | --------------------------------------------------------------------- |
| `app/db.py`              | SQLAlchemy engine/session, three models, tiny auto-migration, `init_db` |
| `app/main.py`            | FastAPI app: schemas, routes, validation, search, context, file I/O    |
| `app/__main__.py`        | Entry point (`python -m app`) running uvicorn                          |
| `app/mcp_server.py`      | MCP tools; each one calls the REST API over HTTP                      |
| `static/index.html`      | Single-file vanilla-JS UI served at `/`                               |
| `tests/test_api.py`      | REST tests using FastAPI's `TestClient`                               |

There are deliberately only three models and no service layer.

### Data model

```
challenges
  id (str, slug PK)   name             description
  created_at          updated_at

entries                                    belonging to exactly one challenge
  id (int PK)         challenge_id (FK)  type            title
  content             author             client_host     status
  file_ids (JSON)     created_at         updated_at

files                                      belonging to exactly one challenge
  id (int PK)         challenge_id (FK)  filename
  path                size               mime_type       created_at
```

Allowed type → status combinations:

| type          | status                    |
| ------------- | ------------------------- |
| `finding`     | `confirmed`               |
| `dead_end`    | `confirmed`               |
| `unconfirmed` | `incomplete` / `invalidated` |

The API enforces this: creating a `finding` or `dead_end` always sets
`confirmed`; `unconfirmed` defaults to `incomplete`.

### Storage & persistence

- SQLite database at `data/ctf.db`.
- Uploaded files at `data/challenges/<challenge>/files/<uuid>_<name>`
  (the original filename is kept in the DB; a uuid prefix avoids collisions).
- `HUB_DATA_DIR` overrides the `data/` location.
- On startup `init_db()` creates tables and adds the `client_host` column to an
  older `entries` table if needed, so existing databases keep working.

### Challenge isolation

Every entry and file query is filtered by `challenge_id`, and `GET`/`DELETE` of a
single entry or file verifies it belongs to the challenge in the path. There is
no cross-challenge endpoint.

### MCP design

`app/mcp_server.py` holds **no business logic**. Each tool issues one HTTP request
to `HUB_URL` (default `http://localhost:8000`). That means:

- The REST API is the single source of truth.
- The MCP process must be launched by the harness on each agent's machine; the
  hub itself only needs to run once (and can bind `0.0.0.0` for remote agents).
- `publish_*` tools attach `socket.gethostname()` as `client_host`.

---

## Quick start

```bash
pip install -r requirements.txt
python -m app
```

Open <http://localhost:8000> for the UI, <http://localhost:8000/docs> for Swagger.

Environment variables:

| Variable         | Default          | Meaning                              |
| ---------------- | ---------------- | ------------------------------------ |
| `HUB_HOST`       | `0.0.0.0`        | Bind address                         |
| `HUB_PORT`       | `8000`           | Port                                 |
| `HUB_DATA_DIR`   | `./data`         | SQLite + file storage                |
| `HUB_URL`        | —                | Used by the MCP server to find the hub |

Run the tests:

```bash
pytest -q
```

---

## Web UI

- **Home** — all challenges with `Findings / Unconfirmed / Dead Ends / Files`
  counts, plus a create form.
- **Challenge page** — tabs for Findings, Unconfirmed, Dead Ends and Files; a
  create form; search; and confirm / invalidate / delete actions.
- **Files** — upload, download, delete.

The UI is intentionally compact: no dashboards, charts or animations.

---

## REST API

Every entry records `client_host` (hostname of the sender). The MCP `publish_*`
tools set it automatically; REST clients may pass it (default `""`).

### curl examples

```bash
# create a challenge
curl -X POST http://localhost:8000/api/challenges \
  -H 'Content-Type: application/json' \
  -d '{"name": "web-admin", "description": "admin panel"}'

# publish a finding
curl -X POST http://localhost:8000/api/challenges/web-admin/entries \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "finding",
    "title": "pickle.loads reachable",
    "content": "POST /api/export reaches pickle.loads()",
    "author": "agent-a"
  }'

# publish a dead end
curl -X POST http://localhost:8000/api/challenges/web-admin/entries \
  -H 'Content-Type: application/json' \
  -d '{"type": "dead_end", "title": "SQLi in /api/users", "content": "parameterized queries", "author": "agent-b"}'

# publish an unconfirmed entry
curl -X POST http://localhost:8000/api/challenges/web-admin/entries \
  -H 'Content-Type: application/json' \
  -d '{"type": "unconfirmed", "title": "Possible command injection", "content": "not verified yet", "author": "agent-c"}'

# read everything known about the challenge (start here when joining)
curl http://localhost:8000/api/challenges/web-admin/context

# search title, content and author
curl 'http://localhost:8000/api/challenges/web-admin/search?q=pickle'

# find an existing challenge, tolerating typos
curl 'http://localhost:8000/api/challenges/resolve?name=web-admn'

# invalidate / promote an unconfirmed entry
curl -X POST http://localhost:8000/api/entries/4/invalidate
curl -X POST http://localhost:8000/api/entries/4/confirm

# files
curl -F 'file=@exploit.py' http://localhost:8000/api/challenges/web-admin/files
curl http://localhost:8000/api/challenges/web-admin/files
curl -O http://localhost:8000/api/challenges/web-admin/files/1
```

### Endpoints

```
POST   /api/challenges
GET    /api/challenges
GET    /api/challenges/resolve?name=...
GET    /api/challenges/{cid}
DELETE /api/challenges/{cid}

POST   /api/challenges/{cid}/entries
GET    /api/challenges/{cid}/entries
GET    /api/challenges/{cid}/entries/{id}
PUT    /api/challenges/{cid}/entries/{id}
DELETE /api/challenges/{cid}/entries/{id}

POST   /api/entries/{id}/confirm
POST   /api/entries/{id}/invalidate

GET    /api/challenges/{cid}/search?q=...

GET    /api/challenges/{cid}/context

GET    /api/challenges/{cid}/files
POST   /api/challenges/{cid}/files
GET    /api/challenges/{cid}/files/{id}
DELETE /api/challenges/{cid}/files/{id}
```

`GET /api/challenges/{cid}/context` returns:

```json
{
  "challenge": { "id": "web-admin", "name": "Web Admin" },
  "findings":    [ { "id": 1, "title": "...", "content": "...", "author": "agent-a", "client_host": "box-1", "status": "confirmed" } ],
  "unconfirmed": [ { "id": 4, "title": "...", "author": "agent-c", "status": "incomplete" } ],
  "dead_ends":   [ { "id": 2, "title": "...", "author": "agent-b" } ],
  "files":       [ { "id": 1, "filename": "exploit.py" } ]
}
```

Newest first within each category; file contents are never included.

---

## MCP server

The MCP server is a thin HTTP client of the REST API, so **start the hub first**
and leave it running:

```bash
python -m app               # terminal 1 — the hub
python -m app.mcp_server    # terminal 2 — stdio MCP server (launched by the harness)
```

Point it elsewhere with `HUB_URL` (e.g. a central hub on another host). Each
agent machine needs a checkout of this repo (or at least the `app/` package) so
the harness can launch `python -m app.mcp_server`.

### Tools

```
create_challenge(name, description="")
list_challenges()
get_challenge_context(challenge_id)
search_challenge(challenge_id, query)
publish_finding(challenge_id, title, content, author)
publish_dead_end(challenge_id, title, content, author)
publish_unconfirmed(challenge_id, title, content, author)
confirm_entry(entry_id)
invalidate_entry(entry_id)
list_challenge_files(challenge_id)
upload_challenge_file(challenge_id, filename, content_base64)
download_challenge_file(challenge_id, file_id)   # returns base64
```

`create_challenge` asks the hub to **resolve the name first** — case and
punctuation are ignored and small typos are tolerated (sequence similarity
≥ 0.8). A typo therefore returns the existing challenge instead of creating a
duplicate:

```json
{ "created": false, "match": "fuzzy", "score": 0.93, "challenge": { "id": "web-admin", ... } }
```

It only creates when nothing similar exists (`{"created": true, ...}`).

### Config snippets

Throughout, replace `/ABS/PATH/TO/HUB` with the absolute path to this repo and
use the Python that has the requirements installed (the repo venv is shown).

#### opencode

`./opencode.json` (project) or `~/.config/opencode/opencode.json` (global):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "ctfhub": {
      "type": "local",
      "command": [
        "/ABS/PATH/TO/HUB/.venv/bin/python",
        "-m",
        "app.mcp_server"
      ],
      "enabled": true,
      "environment": {
        "HUB_URL": "http://localhost:8000",
        "PYTHONPATH": "/ABS/PATH/TO/HUB"
      }
    }
  }
}
```

Restart opencode; tools appear as `ctfhub_get_challenge_context`, etc.

#### Claude Code

`.mcp.json` in the project, or add with the CLI (`--scope user` for global):

```bash
claude mcp add ctfhub --scope user \
  --env HUB_URL=http://localhost:8000 \
  --env PYTHONPATH=/ABS/PATH/TO/HUB \
  -- /ABS/PATH/TO/HUB/.venv/bin/python -m app.mcp_server
```

Equivalent `.mcp.json`:

```json
{
  "mcpServers": {
    "ctfhub": {
      "command": "/ABS/PATH/TO/HUB/.venv/bin/python",
      "args": ["-m", "app.mcp_server"],
      "env": {
        "HUB_URL": "http://localhost:8000",
        "PYTHONPATH": "/ABS/PATH/TO/HUB"
      }
    }
  }
}
```

Tools are named `mcp__ctfhub__get_challenge_context`, etc. Verify with `/mcp`.

#### Codex

`~/.codex/config.toml` (or project-scoped `.codex/config.toml`):

```toml
[mcp_servers.ctfhub]
command = "/ABS/PATH/TO/HUB/.venv/bin/python"
args = ["-m", "app.mcp_server"]
cwd = "/ABS/PATH/TO/HUB"
env = { HUB_URL = "http://localhost:8000" }
```

Or with the CLI:

```bash
codex mcp add ctfhub \
  --env HUB_URL=http://localhost:8000 \
  --env PYTHONPATH=/ABS/PATH/TO/HUB \
  -- /ABS/PATH/TO/HUB/.venv/bin/python -m app.mcp_server
```

Check with `codex mcp list`, or type `/mcp` inside the Codex TUI.

#### Bare `python` (no venv)

If you installed the requirements globally, replace the interpreter with your
`python3` path — the `PYTHONPATH`/`cwd` setting still matters so
`-m app.mcp_server` resolves.

---

## Agent instructions

The MCP server embeds an agent-facing prompt (`INSTRUCTIONS` in
`app/mcp_server.py`) describing the hub workflow: resolve the challenge, read
`get_challenge_context` first, publish findings / dead ends / unconfirmed leads,
promote or invalidate, and attach files.

It is returned as the MCP `instructions` field during initialization
(`MCPServer(..., instructions=INSTRUCTIONS)`). Clients that support server
instructions inject it into the model alongside the tools, so agents learn the
workflow with no extra configuration. Harnesses that ignore server instructions
can copy the same text into their own `AGENTS.md` / `CLAUDE.md`.

---

## Example agent workflow

1. **Agent A** verifies that `/api/export` reaches `pickle.loads()` and publishes
   a **finding**.
2. **Agent B** calls `get_challenge_context("web-admin")`, sees A's finding, and
   investigates that path instead of rediscovering it.
3. **Agent B** confirms `/api/users` is not injectable and publishes a **dead end**.
4. **Agent C** publishes an **unconfirmed** command-injection hypothesis. Another
   agent disproves it, and it is marked `invalidated` — the record stays visible.
5. All three read the same `client_host`/`author` metadata and see which machine
   contributed what.

---

## Project layout

```
.
├── app/
│   ├── __init__.py
│   ├── __main__.py       # python -m app
│   ├── db.py             # engine, models, init_db / migration
│   ├── main.py           # FastAPI app (REST + UI route)
│   └── mcp_server.py     # MCP tools -> REST API
├── static/index.html     # web UI
├── tests/test_api.py
├── requirements.txt
├── pytest.ini
└── README.md
```

---

## Scope / non-goals

This is a prototype and intentionally stays small. It does **not** provide
authentication, users, roles, task assignments, checkpoints, sessions,
embeddings/vector search, message queues, background workers, or orchestration.
SQLite and the local filesystem are deliberate.
