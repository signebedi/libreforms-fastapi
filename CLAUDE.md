# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install for development (Python 3.10+)
python3 -m venv venv && source venv/bin/activate
pip install -e .

# Run the development server
uvicorn libreforms_fastapi.app:app --reload

# Run tests (requires: pip install pytest pytest-env pytest-asyncio httpx)
pytest

# Run a single test
pytest tests/test_api.py::test_name
```

Tests run with `ENVIRONMENT=testing` (set automatically via pytest-env in `pyproject.toml`), which skips dotenv loading and uses an in-memory/testing config. CI (`.github/workflows/python-tests.yml`) runs `pytest` on Python 3.10–3.12 and expects an `./instance` directory to exist.

The package installs a `libreformsctl` CLI (defined in `libreforms_fastapi/cli/__init__.py`, click-based) with commands for production setup and user management: `config`, `uvicorn`, `nginx`, `useradd`, `usermod`, `id`, `reset-apikey`. Most take an `--environment` option.

## Working in this codebase

- **Minimal changes.** Prefer the smallest change to existing code that achieves the result. Show restraint before deviating from established design decisions — avoid unnecessary complexity, especially at the level of architecture.
- **Idiomatic consistency.** Read enough of the surrounding code to make changes idiomatically consistent with the design decisions already made (e.g., routes directly on `app`, forms defined as YAML data, the dual-database split described below).
- **UI style.** New UI elements should look clean, must not use emojis, and should borrow from and conform to the style used elsewhere in the application UI (Jinja2 templates in `app/templates`).
- **Verify before delivering.** Smoke-test the affected functionality — don't hand over changes untested.
- **Data model changes.** If a change alters the SQLAlchemy models, provide a one-shot command to migrate existing databases in `instance/`.

## Architecture

FastAPI implementation of the libreForms spec: a form management system where forms are defined in a YAML config file rather than in code.

**Single-module app.** Nearly all application logic lives in `libreforms_fastapi/app/__init__.py` (~8700 lines). There are no APIRouters — every route is registered directly on `app`:
- `/api/form/*` — form CRUD, search, signing/approval, export
- `/api/auth/*` — user creation, login (JWT), password management, SAML SSO
- `/api/admin/*` — site admin operations (form config edits, groups, relationships, email config)
- `/ui/*` — HTML pages (Jinja2 templates in `app/templates`, `include_in_schema=False`) that consume the API
Shared dependencies (`get_db`, `get_doc_db`, `get_mailer`, `api_key_auth`) and the transaction-log writer are defined near the top of the same file.

**Dual-database design.** Relational data (users, groups, API keys/signing keys, transaction log) uses SQLAlchemy — models built by `get_sqlalchemy_models()` in `utils/sqlalchemy_models.py`, defaulting to SQLite with Postgres/MariaDB as extras. Form submissions live in a separate document database behind the `ManageDocumentDB` ABC in `utils/document_database.py`, with `ManageTinyDB` (default) and `ManageMongoDB` implementations; each form gets its own collection, and document metadata/history/signatures are managed there. That module also defines the domain exceptions (`DocumentDoesNotExist`, `InsufficientPermissions`, `SignatureError`, etc.) the routes catch and map to HTTP errors.

**Forms are data, not code.** The form config is YAML (stored in the instance directory, editable at runtime through the admin API/UI). `utils/pydantic_models.py` turns that YAML into behavior: `load_form_config()` parses it, `get_form_model()` dynamically builds a Pydantic model per form for validation, and `get_form_html()` renders the input fields. Custom YAML tags like `!str` (see `utils/custom_yaml.py`) declare field output types. User models are also built dynamically (`get_user_model()`) because validation rules depend on app config.

**Configuration.** `utils/config.py` provides `get_config(env)` using pydantic-settings; `env` is one of `production`/`development`/`testing`, selected by the `ENVIRONMENT` variable. Production and development read/write dotenv files at `instance/prod.env` and `instance/dev.env`. The app watches the config file for changes and caches config via `get_config_context()`/`clear_config_cache()`.

**Instance directory.** Runtime state lives in `instance/` under the CWD: env files, SQLite databases, the form config YAML, docs markdown, email templates, and their backups. Filenames are prefixed by environment (e.g. `DEV_app.sqlite`). It is created on demand — never treat its contents as source.

**Permissions.** Group-based, stored as strings of the form `<form_name>:<action>` (e.g. `example_form:read_own`, `example_form:update_all`). API auth is via `X-API-KEY` header (sqlalchemy_signing); routes declare `dependencies=[Depends(api_key_auth)]`.

**Tests.** A single `tests/test_api.py` exercises the full app end-to-end via `TestClient`, using session-scoped fixtures that import the app and drop tables on teardown.
