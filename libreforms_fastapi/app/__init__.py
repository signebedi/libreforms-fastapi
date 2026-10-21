# The app is split into modules by area. core.py creates the app and holds the shared config,
# database, auth backend and dependencies, and each of the other modules registers its routes on
# that app when imported, so the order of the imports below is the order routes are registered in.

from libreforms_fastapi.app.core import (
    api_key_auth, app, config, engine, get_config_depends, get_db, get_doc_db, get_mailer,
    Group, logger, models, PasswordReuse, RelationshipType, SessionLocal, signatures, Signing,
    templates, TransactionLog, User, UserRelationship,
)

from libreforms_fastapi.app import (  # noqa: F401
    api_form,
    api_auth,
    api_admin,
    ui_forms,
    ui_default,
    ui_auth,
    ui_admin,
)
