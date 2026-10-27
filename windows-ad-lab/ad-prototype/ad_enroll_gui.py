"""Isolated GUI entry point for current-domain-user phone enrollment."""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(os.path.dirname(ROOT), "app")
sys.path.insert(0, os.path.join(APP, "vendor"))
sys.path.insert(0, ROOT)

from thessley_pam_win.ad_enroll_gui import main

raise SystemExit(main())
