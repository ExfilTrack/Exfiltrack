"""Desktop graphical interface for ExfilTrack.

Owner: Maheesha (Dabarera G. D. M.)
Related issue: #47 - Desktop GUI for analyze, verify, and results review

The package is deliberately split in two:

* :mod:`exfiltrack.gui.controller` holds every piece of logic -- form
  validation, pipeline invocation, result summarising, and digest
  verification -- and imports no GUI toolkit, so it is fully testable on
  headless CI machines.
* :mod:`exfiltrack.gui.app` is the thin tkinter layer on top of it. It is
  only imported when the GUI is actually launched, so
  ``import exfiltrack.gui`` stays safe on machines without a display or
  without tkinter installed.
"""
