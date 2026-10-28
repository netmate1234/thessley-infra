"""Isolated-interpreter entry point for the Windows Task Scheduler task."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from thessley_ad_service.windows_service import main  # noqa: E402

raise SystemExit(main())
