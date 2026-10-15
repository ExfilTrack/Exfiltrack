"""Support launching the GUI with ``python -m exfiltrack.gui``.

Owner: Maheesha (Dabarera G. D. M.)
Related issue: #47 - Desktop GUI for analyze, verify, and results review
"""

from exfiltrack.gui.app import main

if __name__ == "__main__":
    raise SystemExit(main())
