"""Shared test helpers for the agent-sandbox test suite.

The orchestrator lives at ``scripts/agent-sandbox.py``. It is importable (it
guards ``main()`` behind ``if __name__ == "__main__"``), but it is not on the
normal import path, so we load it explicitly via SourceFileLoader.

Each loaded instance gets its own module object, which lets individual tests
point ``XDG_CONFIG_HOME`` / ``XDG_DATA_HOME`` at temp dirs without clobbering
global state shared between tests.
"""

import contextlib
import importlib.machinery
import importlib.util
import io
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "agent-sandbox.py"


@contextlib.contextmanager
def quiet(tty=False):
    """Suppress stdout/stderr produced by the orchestrator during a test.

    The script prints user-facing prompts and warnings; tests assert on return
    values, not output, so we silence it to keep test output readable.

    Because ``redirect_stdout`` replaces ``sys.stdout``, code that calls
    ``sys.stdout.isatty()`` would otherwise see the buffer (always False). Pass
    ``tty=True`` to make the suppressed stdout report itself as a TTY so the
    interactive code path can still be exercised.
    """
    class _Buf(io.StringIO):
        def isatty(self):
            return tty

    with contextlib.redirect_stdout(_Buf()), contextlib.redirect_stderr(_Buf()):
        yield


def load_agent_sandbox(xdg_config=None, xdg_data=None):
    """Load scripts/agent-sandbox.py as a fresh module.

    Optionally override the XDG paths so the module reads/writes config and the
    trust store under a temporary directory instead of the real user config.
    """
    loader = importlib.machinery.SourceFileLoader("agent_sandbox_under_test", str(SCRIPT_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)

    if xdg_config is not None:
        module.XDG_CONFIG_HOME = Path(xdg_config)
    if xdg_data is not None:
        module.XDG_DATA_HOME = Path(xdg_data)
    return module
