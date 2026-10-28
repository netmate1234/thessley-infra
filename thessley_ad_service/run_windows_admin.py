"""Isolated-interpreter entry point for local AD API administration."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from thessley_ad_service.windows_admin_cli import main  # noqa: E402

raise SystemExit(main())
