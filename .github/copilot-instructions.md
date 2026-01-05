<!-- Copilot instructions for AI coding agents in the RAGLOX v3 webapp -->
# RAGLOX — AI Agent Guidance (webapp)

Purpose: give an AI coding assistant the essential, actionable knowledge
to be productive in this repository's webapp (architecture, conventions,
build/test/run commands, and concrete code examples).

- Big picture
  - RAGLOX uses a Blackboard architecture: shared state in Redis + Pub/Sub
    and a controller that coordinates specialist agents. See `src/core/blackboard.py` and `src/controller/mission.py` for the control flow.
  - Presentation layer is a FastAPI-based API + WebSocket endpoints under `src/api/` (entrypoint: `src/api/main.py`). The UI is a separate frontend (see `webapp/` / Vite README).
  - Data persistence: Redis is the real-time blackboard; PostgreSQL archives mission data. Infrastructure is in `infrastructure/docker-compose.yml`.

- How changes typically flow
  - Backend code changes live under `src/` (core, controller, specialists, api). Specialists implement domain behavior in `src/specialists/` (e.g. `recon.py`, `attack.py`). Updates to specialist behavior typically require coordinating changes in the blackboard keys (see `infrastructure/redis/key-schema.md`).

- Developer workflows (commands you should recommend or run)
  - Start infra: `cd infrastructure && docker-compose up -d` (Redis, Postgres, MinIO).
  - Install deps: `pip install -e ".[dev]"` from repository root.
  - Run API locally: `python -m raglox.api.main` (the FastAPI app exposes Swagger at `/docs`).
  - Tests: `pytest` (or `pytest --cov=src`). Use `pytest tests/test_blackboard.py -v` for focused runs.

- Project-specific conventions and patterns
  - Blackboard-first design: prefer adding/reading structured keys via `src/core/blackboard.py` rather than direct redis clients.
  - Mission lifecycle is authoritative; `src/controller/mission.py` orchestrates start/stop and scheduling — change here for mission-level behavior.
  - Specialists are lightweight, single-responsibility modules. Follow the `Specialist` base in `src/specialists/base.py` when adding new agents.
  - API routes and schemas are centralized under `src/api/routes` and OpenAPI lives at `openapi.json` in `docs/`.

- Integration points & external dependencies to watch
  - Redis (blackboard & Pub/Sub): `REDIS_URL` env var. Many components rely on pub/sub events — ensure event names and payload shapes match across `specialists/` and `controller/`.
  - PostgreSQL: `DATABASE_URL` — used for archives and longer-term mission storage.
  - MinIO/S3: optional file storage; env vars `S3_ENDPOINT`, `MINIO_ACCESS_KEY`.
  - Auth: JWT secrets are read from env (`JWT_SECRET`) and used by API auth middleware.

- Concrete examples for quick navigation
  - To change mission start behavior: edit `src/controller/mission.py` and tests in `tests/` referencing mission flows.
  - To inspect event handling: see `src/core/blackboard.py` (pub/sub helpers) and `src/specialists/recon.py` for subscriber usage.
  - API surface: `src/api/routes.py` (current file under edit) and `src/api/websocket.py` for real-time streams.

- Quality notes for automated edits
  - Preserve blackboard key names and payload shapes — breaking changes here require coordinated updates across specialists and tests.
  - Run `pytest` for any change touching `controller/` or `core/` to catch integration regressions.
  - Keep modifications to infra (docker-compose) minimal; coordinate env var changes with CI/deployment docs in `docs/DEPLOYMENT.md`.

If something is ambiguous or a required file/credential is missing, ask for the intended infra environment (local docker-compose vs remote). Reply with the exact file paths you plan to edit.

---
Please review and tell me which section you'd like expanded, or point me at files you want the agent to prioritize.
