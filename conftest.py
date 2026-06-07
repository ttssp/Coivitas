"""Repository-root pytest sys.path injection.

The Python SDK lives at ``packages/sdk-python/src/coivitas``. Running pytest
from the repository root requires that path on sys.path so
``from coivitas import ...`` resolves without an editable install.

This file injects ``packages/sdk-python/src`` at ``sys.path[0]`` once per
process (idempotent), so contributors can ``git clone && python -m pytest``
with no install step. The path matches ``packages/sdk-python/pyproject.toml``'s
``[tool.setuptools.packages.find] where = ["src"]`` declaration.

Invariants
----------
1. Inject at most once (``if path not in sys.path``, idempotent).
2. Inject at ``sys.path[0]`` so a fresh source tree wins over any stale
   editable install or site-packages copy of the same package name.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Repository root = directory containing this file
_REPO_ROOT = Path(__file__).resolve().parent
# Python SDK source root (PEP 420 namespace container)
_SDK_PYTHON_SRC = _REPO_ROOT / "packages" / "sdk-python" / "src"

# Only takes effect when the path exists and is not yet injected; idempotent
if _SDK_PYTHON_SRC.is_dir():
    sdk_path_str = str(_SDK_PYTHON_SRC)
    if sdk_path_str not in sys.path:
        # Insert at the front: override any stale editable install / site-packages package of the same name
        sys.path.insert(0, sdk_path_str)
