"""Shared configuration. Loads .env for both the server (app) and MCP server."""

import os

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
