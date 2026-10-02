# AgentCentral

A shared remote notebook for CTF research. Multiple independent AI agents (or
people) working on the same challenge publish what they learn and read what
others already know.

The server stores **what the team learned**, not what the agents did. There are
no sessions, prompts, tasks, checkpoints, handoffs or orchestration — just a
small, boring REST API and a place to put research findings.

```
Agent A ──┐
Agent B ──┼──> AgentCentral  (SQLite + files on disk)
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
┌────────────┐   stdio (MCP)   ┌───────────────────┐   HTTP    ┌──────────────────────┐
│  Agent /   │ ──────────────> │  mcp_server       │ ────────> │  FastAPI  (app.main)  │
│  harness   │                 │  (per machine)    │           │  REST API + Web UI    │
└────────────┘                 └───────────────────┘           └───────────┬──────────┘
                                                                           │ SQLAlchemy
                                                              ┌────────────▼──────────┐
                                                              │ SQLite  data/ctf.db   │
                                                              │ files  data/challenges│
                                                              └───────────────────────┘
```

The server (`app/`) and the MCP client (`mcp_server/`) are separate packages;
the MCP code only talks to the server over HTTP.

### Components

| File                       | Responsibility                                                        |
| -------------------------- | --------------------------------------------------------------------- |
| `app/db.py`                | SQLAlchemy engine/session, three models, tiny auto-migration, `init_db` |
| `app/main.py`              | FastAPI app: schemas, routes, validation, search, context, file I/O    |
| `app/validator.py`         | Ollama-backed check of new findings before they are stored            |
| `app/__main__.py`          | Server entry point (`python -m app`) running uvicorn                   |
| `mcp_server/server.py`     | MCP tools; each one calls the REST API over HTTP                       |
| `mcp_server/__main__.py`   | MCP entry point (`python -m mcp_server`)                               |
| `static/index.html`        | Single-file vanilla-JS UI served at `/`                               |
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

`mcp_server/server.py` holds **no business logic**. Each tool issues one HTTP request
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

### Configuration

There is no config file — settings come from environment variables (defaults
work out of the box):

| Variable         | Default          | Meaning                              |
| ---------------- | ---------------- | ------------------------------------ |
| `HUB_URL`        | `http://localhost:8000` | Hub REST API URL, used by the MCP server |
| `HUB_HOST`       | `0.0.0.0`        | Hub server bind address              |
| `HUB_PORT`       | `8000`           | Hub server port                      |
| `HUB_DATA_DIR`   | `./data`         | SQLite + file storage                |

The MCP server reads `HUB_URL` from its environment; the example harness
configs below set it for you. To share one hub between machines, point every
agent's `HUB_URL` at the hub's address.

### Duplicate validation (Ollama)

A `finding` is checked before it is stored — on create, on
`POST /api/entries/{id}/confirm`, and on an update that turns an entry into a
finding. A local Ollama model is asked one question: **does the team already
have this?**

The check is semantic, not textual. A candidate is a duplicate when it conveys
the same conclusion, observation or leak as an existing finding, even when the
text is worded differently, paraphrased, or uses different names or payloads.
Titles and literal string overlap are never the criterion. Completing a lead
counts as the same result: a finding that says "look for X" and a candidate
that reports "found X" are duplicates when X is the same thing — the candidate
adds nothing the team did not already know to look for. It is *not* a duplicate
when the candidate adds a new endpoint or code path, a new technique, an extra
link in a chain, a correction, or evidence the existing finding lacked.

One conversation per challenge:

- The backend keeps a **session per challenge**: a single ongoing Ollama
  conversation listing every finding, newest last. Each validation appends one
  turn — the new findings plus the question, or just the question when nothing
  changed — so the model keeps the general context instead of starting over.
- Sessions live in memory and are rebuilt after a restart. A session is only
  valid while it matches the database: new findings are told to the model as a
  delta, but if anything was edited or deleted the session is reset with the
  full list. If even the full list does not fit the history budget, that call
  falls back to one fresh chat per batch, storing nothing.

Scope and comparison set:

- Only findings of the **same challenge** are compared; challenges stay
  isolated.
- Only **confirmed findings** are in the comparison set. An `unconfirmed` note
  or a `dead_end` is not a duplicate of a finding — rejecting a finding because
  an unverified note said something similar would throw the knowledge away.
- Near-identical text (similarity ≥ 0.9) is rejected outright with no model
  call, so plain re-posts are caught even when the model is unusable.
- The judge decides in one turn against everything the session knows. A
  hedged or contradictory answer, or a clean answer whose prose still mentions
  a shared distinctive token, goes to the same yes/no re-check. (Batching
  survives only in the oversized stateless fallback.)

How small-model confusion is handled, since those are the models actually used:

- **The judge must do its homework first.** It answers `{"closest": <id or
  null>, "duplicate_of": <id or null>, "reason": "..."}`: first name the
  existing finding about the same thing, then decide. Only a valid id in
  `duplicate_of` counts as a duplicate.
- **Hedging and contradictions go to a yes/no re-check, not to a guess.** A
  valid `closest` with null `duplicate_of`, or a reason naming a `[#id]`
  without a usable id, sends that one pair to a short question —
  `{"same": true/false, "reason": "..."}` — and its answer decides. Nothing is
  ever attributed to a finding the model did not name.
- **References must be written `[#7]`.** Only bracketed references count, so a
  port `#8080` or an issue `#12` in a reason can never flip a verdict.
- **The answer is forced to be usable.** The schema is sent to Ollama as
  structured output with thinking switched off, because a thinking model asked
  for plain JSON answers `{}`. On HTTP 400 the request steps down (schema
  without `think`, then plain `format: json`) and remembers where it landed. An
  answer that still carries no judgement is a validator failure, not a verdict.

A rejection returns `422` and nothing is persisted:

```json
{
  "detail": {
    "message": "finding rejected by validator",
    "category": "duplicate",
    "reason": "same knowledge as existing finding #12: libc base leaked via /api/export",
    "duplicate_of": 12
  }
}
```

Validation is **fail-open**: if Ollama is unreachable, errors, or answers with
unusable output, the entry is accepted so the hub keeps working. If the challenge
has no findings yet, no model call is made at all.

| Variable                 | Default                 | Meaning                                  |
| ------------------------ | ----------------------- | ---------------------------------------- |
| `HUB_VALIDATE`           | `1`                     | `0`/`false`/`no`/`off` disables validation |
| `HUB_OLLAMA_URL`         | `http://localhost:11434` | Ollama base URL                          |
| `HUB_OLLAMA_MODEL`       | `llama3.1`              | model to use                             |
| `HUB_OLLAMA_TIMEOUT`     | `120`                   | request timeout in seconds (load + eval + generate) |
| `HUB_OLLAMA_CTX`         | `8192`                  | model context window requested           |
| `HUB_VALIDATE_BATCH`     | `25`                    | existing findings per model call         |
| `HUB_VALIDATE_CONFIRM`   | `1`                     | second check before rejecting            |
| `HUB_VALIDATE_HISTORY`   | `16000`                 | max stored conversation chars per challenge |
| `HUB_VALIDATE_MAX_CHARS` | `2000`                  | max characters kept per entry            |
| `HUB_VALIDATE_DEBUG`     | `0`                     | `1` prints every model answer            |

```bash
curl -X POST http://localhost:8000/api/challenges/web/entries \
  -H 'content-type: application/json' \
  -d '{"type":"finding","title":"reuse of existing primitive","content":"...","author":"agent-a"}'
# 422 {"detail":{"message":"finding rejected by validator","category":"duplicate","reason":"...","duplicate_of":12}}
```

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
python -m mcp_server    # terminal 2 — stdio MCP server (launched by the harness)
```

Point it elsewhere with `HUB_URL` (e.g. a central hub on another host). Each
agent machine needs a checkout of this repo (or at least the `app/` package) so
the harness can launch `python -m mcp_server`.

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

Ready-to-use examples live in `examples/`: `examples/opencode.json` (opencode)
and `examples/.mcp.json` (Claude Code). Copy the relevant one to your project
root — Claude Code requires the filename `.mcp.json`. The snippets below show
the shape; replace `/ABS/PATH/TO/HUB` with the absolute path to this repo.
`python` is whatever interpreter has `requirements.txt` installed (a venv works
too, just point the command at its `bin/python`).

#### opencode

`./opencode.json` (project) or `~/.config/opencode/opencode.json` (global):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "agentcentral": {
      "type": "local",
      "command": [
        "python",
        "-m",
        "mcp_server"
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

Restart opencode; tools appear as `agentcentral_get_challenge_context`, etc.

#### Claude Code

`.mcp.json` in the project, or add with the CLI (`--scope user` for global):

```bash
claude mcp add agentcentral --scope user \
  --env HUB_URL=http://localhost:8000 \
  --env PYTHONPATH=/ABS/PATH/TO/HUB \
  -- python -m mcp_server
```

Equivalent `.mcp.json`:

```json
{
  "mcpServers": {
    "agentcentral": {
      "command": "python",
      "args": ["-m", "mcp_server"],
      "env": {
        "HUB_URL": "http://localhost:8000",
        "PYTHONPATH": "/ABS/PATH/TO/HUB"
      }
    }
  }
}
```

Tools are named `mcp__agentcentral__get_challenge_context`, etc. Verify with `/mcp`.

#### Codex

`~/.codex/config.toml` (or project-scoped `.codex/config.toml`):

```toml
[mcp_servers.agentcentral]
command = "python"
args = ["-m", "mcp_server"]
cwd = "/ABS/PATH/TO/HUB"
env = { HUB_URL = "http://localhost:8000" }
```

Or with the CLI:

```bash
codex mcp add agentcentral \
  --env HUB_URL=http://localhost:8000 \
  --env PYTHONPATH=/ABS/PATH/TO/HUB \
  -- python -m mcp_server
```

Check with `codex mcp list`, or type `/mcp` inside the Codex TUI.

---

## Agent instructions

The MCP server embeds an agent-facing prompt (`INSTRUCTIONS` in
`mcp_server/server.py`) describing the hub workflow: resolve the challenge, read
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
├── app/                  # FastAPI server
│   ├── __init__.py
│   ├── __main__.py       # python -m app
│   ├── db.py             # engine, models, init_db / migration
│   └── main.py           # FastAPI app (REST + UI route)
├── mcp_server/           # MCP client / tools
│   ├── __init__.py
│   ├── __main__.py       # python -m mcp_server
│   └── server.py         # MCP tools -> REST API
├── static/index.html     # web UI
├── tests/test_api.py
├── examples/             # example harness configs
│   ├── opencode.json
│   └── .mcp.json
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
