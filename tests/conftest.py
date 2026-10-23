"""
Test bootstrap: run the whole suite inside its own temporary instance directory.

The app derives every runtime path (the SQLite database, TinyDB collections, the form
config YAML, signing keys) from the current working directory at import time. Running
pytest from a developer checkout would otherwise read and mutate that checkout's
instance/ directory, and the suite is sensitive to whatever stale state it holds
(see excludes/issues.md, issue 31).

This module runs at collection time, before tests/test_api.py imports the app, so the
chdir below takes effect before any instance path is computed. It also defaults
ENVIRONMENT to "testing" so that a bare `pytest` without the pytest-env plugin cannot
run the suite against (and tear down) a development database.
"""
import os, atexit, shutil, tempfile

os.environ.setdefault("ENVIRONMENT", "testing")

_original_cwd = os.getcwd()
_test_root = tempfile.mkdtemp(prefix="libreforms_test_")
os.makedirs(os.path.join(_test_root, "instance"), exist_ok=True)
os.chdir(_test_root)


@atexit.register
def _cleanup_test_instance_directory():
    os.chdir(_original_cwd)
    shutil.rmtree(_test_root, ignore_errors=True)
