"""Thin MCP interface over the CTFHub REST API.

Run with:  python -m mcp_server
Configure the hub location with HUB_URL in the project .env
(default http://localhost:8000).
"""

import os
import socket

import httpx
from mcp.server.mcpserver import MCPServer

HUB_URL = os.environ.get("HUB_URL", "http://localhost:8000").rstrip("/")

# Hostname of the machine running this MCP client. Stored on every entry so
# other agents can tell which machine a piece of research came from.
CLIENT_HOST = socket.gethostname()

# Guidance sent to MCP clients during initialization. Clients that support
# server instructions inject this into the model alongside the tools, so agents
# learn the hub workflow without any per-harness configuration.
INSTRUCTIONS = """\
# CTFHub — agent instructions

You are working on a CTF challenge alongside other independent agents. The
**CTFHub** is a shared notebook exposed to you as MCP tools. Use it to
learn what the team already knows before you start, and to leave behind what you
learn so others do not repeat your work.

Store **what the team learned** — not what you did. Never publish prompts,
conversations, plans, sessions, checkpoints, token usage or agent state. Only
research knowledge.

Tool names may be prefixed by your harness (for example
`ctfhub_get_challenge_context` or `mcp__ctfhub__get_challenge_context`); the
names below are the suffixes.

## Every session

1. **Identify the challenge.**
   - If you know the name, call `create_challenge(name)`. It resolves existing
     challenges first (case/punctuation-insensitive, tolerant of small typos),
     so a typo returns the existing challenge instead of creating a duplicate.
     The returned `challenge.id` is the canonical id — use it everywhere.
   - If you are unsure, call `list_challenges()`.

2. **Read before you work.** Call `get_challenge_context(challenge_id)`. It
   returns `findings`, `unconfirmed`, `dead_ends` and `files` for that
   challenge. Treat it as the team's current state of knowledge. Do not
   rediscover what is already there. Before digging into a specific path, also
   call `search_challenge(challenge_id, query)`.

3. **Do the work.**

4. **Publish what you learned** using exactly one of:
   - `publish_finding(challenge_id, title, content, author)` — verified and
     reliable. Other agents may build on it.
   - `publish_dead_end(challenge_id, title, content, author)` — a path you
     **actually investigated** that did not work.
   - `publish_unconfirmed(challenge_id, title, content, author)` — a promising
     lead you have not verified yet.

5. **Keep the record honest.**
   - Verified an unconfirmed lead -> `confirm_entry(entry_id)` (becomes a
     finding).
   - Disproved an unconfirmed lead -> `invalidate_entry(entry_id)` (kept, marked
     `invalidated`). Never delete another agent's entry.

## Writing an entry

- `author`: a short, stable name for you, e.g. `agent-a`, `claude-web`,
  `codex-rev`. Your machine's hostname is recorded automatically.
- `title`: one specific line. `pickle.loads reachable through /api/export`.
- `content`: the concrete evidence — endpoint, parameter, payload, command,
  observed output, and why it matters. Not "explored the endpoint".
- `dead_end` is **not** for random thoughts or untested ideas; use
  `unconfirmed` for those.
- Search/context first so you do not publish a duplicate.
- Never publish flags, credentials or secrets.

## Files as evidence

- `upload_challenge_file(challenge_id, filename, content_base64)` — attach
  exploits, request dumps, captures, binaries, libc, notes.
- `list_challenge_files(challenge_id)` — see what is attached.
- `download_challenge_file(challenge_id, file_id)` — retrieve one (base64).

Files belong to one challenge and are visible to every agent on it.

## Hard rules

- Always pass the correct `challenge_id`. Challenges are isolated: never mix
  `web-admin` data into `pwn-vault`.
- Publish as you go; do not hoard findings until the end.
- If the hub tools are unavailable, tell the user to start the hub
  (`python -m app`) and check the MCP configuration. Do not fake results.
"""

mcp = MCPServer("ctfhub", instructions=INSTRUCTIONS)


async def _request(method: str, path: str, **kwargs):
    async with httpx.AsyncClient(base_url=HUB_URL, timeout=30) as client:
        response = await client.request(method, path, **kwargs)
        response.raise_for_status()
        if response.headers.get("content-type", "").startswith("application/json"):
            return response.json()
        return response.text


def _entry_body(entry_type: str, title: str, content: str, author: str) -> dict:
    return {
        "type": entry_type,
        "title": title,
        "content": content,
        "author": author,
        "client_host": CLIENT_HOST,
    }


@mcp.tool()
async def create_challenge(name: str, description: str = "") -> dict:
    """Create a challenge if it does not already exist.

    The hub is checked first for a challenge with the same or a similar name
    (case/punctuation-insensitive, tolerant of small typos), so a misspelled
    name will not create a duplicate. Returns the existing challenge when a
    match is found, with match = "exact" or "fuzzy".
    """
    resolved = await _request("GET", "/api/challenges/resolve", params={"name": name})
    if resolved.get("challenge"):
        return {
            "created": False,
            "match": resolved["match"],
            "score": resolved["score"],
            "challenge": resolved["challenge"],
        }
    created = await _request(
        "POST", "/api/challenges", json={"name": name, "description": description}
    )
    return {"created": True, "match": "created", "challenge": created}


@mcp.tool()
async def list_challenges() -> list:
    """List all challenges with entry counts."""
    return await _request("GET", "/api/challenges")


@mcp.tool()
async def get_challenge_context(challenge_id: str) -> dict:
    """Get everything currently known about a challenge."""
    return await _request("GET", f"/api/challenges/{challenge_id}/context")


@mcp.tool()
async def search_challenge(challenge_id: str, query: str) -> list:
    """Search a challenge's entries by title, content or author."""
    return await _request(
        "GET", f"/api/challenges/{challenge_id}/search", params={"q": query}
    )


@mcp.tool()
async def publish_finding(
    challenge_id: str, title: str, content: str, author: str
) -> dict:
    """Publish a confirmed finding."""
    return await _request(
        "POST",
        f"/api/challenges/{challenge_id}/entries",
        json=_entry_body("finding", title, content, author),
    )


@mcp.tool()
async def publish_dead_end(
    challenge_id: str, title: str, content: str, author: str
) -> dict:
    """Publish a dead end (an investigated path that did not work)."""
    return await _request(
        "POST",
        f"/api/challenges/{challenge_id}/entries",
        json=_entry_body("dead_end", title, content, author),
    )


@mcp.tool()
async def publish_unconfirmed(
    challenge_id: str, title: str, content: str, author: str
) -> dict:
    """Publish unconfirmed information (not yet verified)."""
    return await _request(
        "POST",
        f"/api/challenges/{challenge_id}/entries",
        json=_entry_body("unconfirmed", title, content, author),
    )


@mcp.tool()
async def confirm_entry(entry_id: int) -> dict:
    """Promote an unconfirmed entry to a confirmed finding."""
    return await _request("POST", f"/api/entries/{entry_id}/confirm")


@mcp.tool()
async def invalidate_entry(entry_id: int) -> dict:
    """Mark an unconfirmed entry as invalidated (kept in the record, not deleted)."""
    return await _request("POST", f"/api/entries/{entry_id}/invalidate")


@mcp.tool()
async def list_challenge_files(challenge_id: str) -> list:
    """List metadata for files belonging to a challenge."""
    return await _request("GET", f"/api/challenges/{challenge_id}/files")


@mcp.tool()
async def upload_challenge_file(
    challenge_id: str, filename: str, content_base64: str
) -> dict:
    """Upload a file to a challenge (content must be base64 encoded)."""
    import base64

    raw = base64.b64decode(content_base64)
    async with httpx.AsyncClient(base_url=HUB_URL, timeout=60) as client:
        response = await client.post(
            f"/api/challenges/{challenge_id}/files",
            files={"file": (filename, raw)},
        )
        response.raise_for_status()
        return response.json()


@mcp.tool()
async def download_challenge_file(challenge_id: str, file_id: int) -> str:
    """Download a challenge file and return its content as base64."""
    import base64

    async with httpx.AsyncClient(base_url=HUB_URL, timeout=60) as client:
        response = await client.get(
            f"/api/challenges/{challenge_id}/files/{file_id}"
        )
        response.raise_for_status()
        return base64.b64encode(response.content).decode("ascii")
