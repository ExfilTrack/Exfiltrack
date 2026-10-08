"""Tkinter desktop front end for ExfilTrack.

Owner: Maheesha (Dabarera G. D. M.)
Related issue: #47 - Desktop GUI for analyze, verify, and results review

A thin layer over :mod:`exfiltrack.gui.controller`: it draws the case form,
runs analysis and verification on a worker thread so the window stays
responsive, and renders the summaries the controller produces. tkinter is
the only GUI toolkit used, so the GUI adds no new dependencies.

Threading rule observed throughout: widgets are only ever touched from the
main (GUI) thread. Worker threads communicate through a
:class:`queue.Queue`, which the main thread drains with ``after()``.
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Any

from exfiltrack import __tool_name__, __version__
from exfiltrack.config import ExfilTrackError
from exfiltrack.gui import controller
from exfiltrack.gui.controller import AnalysisSummary, VerificationSummary

# The statement issue #14 requires to be visible wherever results are shown.
DISCLAIMER = (
    "ExfilTrack identifies activity consistent with possible USB-based data "
    "exfiltration. Temporal correlation alone does not prove that a file was copied."
)

_QUEUE_POLL_MS = 100


def _open_in_file_manager(path: Path) -> None:
    """Open *path* with the platform's file manager / default handler."""
    startfile: Any = getattr(os, "startfile", None)  # Windows-only; absent elsewhere
    if startfile is not None:
        startfile(str(path))
    else:
        webbrowser.open(path.as_uri())


class ExfilTrackApp:
    """The main window: case form, progress log, findings table, and actions."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(f"{__tool_name__} {__version__}")
        self.root.minsize(820, 720)

        self._queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._worker: threading.Thread | None = None
        self._summary: AnalysisSummary | None = None

        self.case_id_var = tk.StringVar()
        self.examiner_var = tk.StringVar()
        self.mode_var = tk.StringVar(value=controller.OFFLINE_MODE)
        self.evidence_var = tk.StringVar()
        self.case_dir_var = tk.StringVar()
        self.case_dir_label_var = tk.StringVar(value="Case output directory:")
        self.status_var = tk.StringVar(value="Idle.")
        self.summary_var = tk.StringVar(value="No analysis run yet.")
        self.integrity_var = tk.StringVar(value="")

        self._build_widgets()
        self._on_mode_changed()
        self.root.after(_QUEUE_POLL_MS, self._poll_queue)

    # ------------------------------------------------------------------
    # Widget construction
    # ------------------------------------------------------------------

    def _build_widgets(self) -> None:
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill=tk.BOTH, expand=True)
        outer.rowconfigure(1, weight=1)
        outer.rowconfigure(2, weight=1)
        outer.columnconfigure(0, weight=1)

        self._build_case_form(outer)
        self._build_progress_area(outer)
        self._build_results_area(outer)

        footer = ttk.Label(
            outer, text=DISCLAIMER, foreground="#8a6d3b", wraplength=780, justify=tk.LEFT
        )
        footer.grid(row=3, column=0, sticky="ew", pady=(8, 0))

    def _build_case_form(self, outer: ttk.Frame) -> None:
        form = ttk.LabelFrame(outer, text="Case", padding=8)
        form.grid(row=0, column=0, sticky="ew")
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Case ID:").grid(row=0, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.case_id_var).grid(
            row=0, column=1, columnspan=2, sticky="ew", padx=(6, 0), pady=2
        )
        ttk.Label(form, text="Examiner:").grid(row=1, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.examiner_var).grid(
            row=1, column=1, columnspan=2, sticky="ew", padx=(6, 0), pady=2
        )

        ttk.Label(form, text="Mode:").grid(row=2, column=0, sticky="w")
        modes = ttk.Frame(form)
        modes.grid(row=2, column=1, columnspan=2, sticky="w", padx=(6, 0), pady=2)
        ttk.Radiobutton(
            modes,
            text="Offline evidence directory",
            value=controller.OFFLINE_MODE,
            variable=self.mode_var,
            command=self._on_mode_changed,
        ).pack(side=tk.LEFT)
        ttk.Radiobutton(
            modes,
            text="Live acquisition (this machine; run elevated)",
            value=controller.LIVE_MODE,
            variable=self.mode_var,
            command=self._on_mode_changed,
        ).pack(side=tk.LEFT, padx=(12, 0))

        ttk.Label(form, text="Evidence directory:").grid(row=3, column=0, sticky="w")
        self.evidence_entry = ttk.Entry(form, textvariable=self.evidence_var)
        self.evidence_entry.grid(row=3, column=1, sticky="ew", padx=(6, 0), pady=2)
        self.evidence_button = ttk.Button(
            form, text="Browse...", command=lambda: self._browse_directory(self.evidence_var)
        )
        self.evidence_button.grid(row=3, column=2, padx=(6, 0), pady=2)

        ttk.Label(form, textvariable=self.case_dir_label_var).grid(row=4, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.case_dir_var).grid(
            row=4, column=1, sticky="ew", padx=(6, 0), pady=2
        )
        ttk.Button(
            form, text="Browse...", command=lambda: self._browse_directory(self.case_dir_var)
        ).grid(row=4, column=2, padx=(6, 0), pady=2)

        self.verify_button = ttk.Button(
            form, text="Verify Case Integrity...", command=self._on_verify_clicked
        )
        self.verify_button.grid(row=5, column=0, sticky="w", pady=(8, 0))
        self.run_button = ttk.Button(form, text="Run Analysis", command=self._on_run_clicked)
        self.run_button.grid(row=5, column=1, columnspan=2, sticky="e", pady=(8, 0))

    def _build_progress_area(self, outer: ttk.Frame) -> None:
        middle = ttk.LabelFrame(outer, text="Progress", padding=8)
        middle.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        middle.rowconfigure(1, weight=1)
        middle.columnconfigure(0, weight=1)

        self.progress_bar = ttk.Progressbar(middle, mode="indeterminate")
        self.progress_bar.grid(row=0, column=0, sticky="ew")
        ttk.Label(middle, textvariable=self.status_var).grid(
            row=0, column=1, sticky="w", padx=(8, 0)
        )
        self.log = ScrolledText(middle, height=8, state=tk.DISABLED, wrap=tk.WORD)
        self.log.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(6, 0))

    def _build_results_area(self, outer: ttk.Frame) -> None:
        results = ttk.LabelFrame(
            outer, text="Findings (double-click a row for the score breakdown)", padding=8
        )
        results.grid(row=2, column=0, sticky="nsew", pady=(8, 0))
        results.rowconfigure(0, weight=1)
        results.columnconfigure(0, weight=1)

        columns = ("device", "start", "score", "confidence", "boundaries")
        self.findings = ttk.Treeview(results, columns=columns, show="headings", height=8)
        self.findings.heading("device", text="Device")
        self.findings.heading("start", text="Session start (UTC)")
        self.findings.heading("score", text="Risk score")
        self.findings.heading("confidence", text="Confidence")
        self.findings.heading("boundaries", text="Boundaries")
        self.findings.column("device", width=200)
        self.findings.column("start", width=180)
        self.findings.column("score", width=80, anchor=tk.E)
        self.findings.column("confidence", width=90)
        self.findings.column("boundaries", width=180)
        scrollbar = ttk.Scrollbar(results, orient=tk.VERTICAL, command=self.findings.yview)
        self.findings.configure(yscrollcommand=scrollbar.set)
        self.findings.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.findings.bind("<Double-1>", self._on_finding_double_clicked)

        ttk.Label(results, textvariable=self.summary_var, wraplength=760, justify=tk.LEFT).grid(
            row=1, column=0, columnspan=2, sticky="w", pady=(6, 0)
        )
        ttk.Label(results, textvariable=self.integrity_var).grid(
            row=2, column=0, columnspan=2, sticky="w"
        )

        actions = ttk.Frame(results)
        actions.grid(row=3, column=0, columnspan=2, sticky="e", pady=(8, 0))
        self.open_html_button = ttk.Button(
            actions, text="Open HTML Report", command=self._on_open_html, state=tk.DISABLED
        )
        self.open_html_button.pack(side=tk.LEFT)
        self.open_folder_button = ttk.Button(
            actions, text="Open Output Folder", command=self._on_open_folder, state=tk.DISABLED
        )
        self.open_folder_button.pack(side=tk.LEFT, padx=(8, 0))

    # ------------------------------------------------------------------
    # Event handlers (main thread)
    # ------------------------------------------------------------------

    def _browse_directory(self, target: tk.StringVar) -> None:
        chosen = filedialog.askdirectory(parent=self.root)
        if chosen:
            target.set(chosen)

    def _on_mode_changed(self) -> None:
        live = self.mode_var.get() == controller.LIVE_MODE
        state = tk.DISABLED if live else tk.NORMAL
        self.evidence_entry.configure(state=state)
        self.evidence_button.configure(state=state)
        self.case_dir_label_var.set("New case directory:" if live else "Case output directory:")

    def _on_run_clicked(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        self._clear_results()
        self._append_log(f"Starting a {self.mode_var.get()} analysis run...")
        self._set_running(True)
        self._worker = threading.Thread(
            target=self._run_analysis_worker,
            kwargs={
                "mode": self.mode_var.get(),
                "evidence_dir": self.evidence_var.get(),
                "case_dir": self.case_dir_var.get(),
                "case_id": self.case_id_var.get(),
                "examiner": self.examiner_var.get(),
            },
            daemon=True,
        )
        self._worker.start()

    def _on_verify_clicked(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        chosen = filedialog.askdirectory(parent=self.root, title="Select the case directory")
        if not chosen:
            return
        self._append_log(f"Verifying recorded digests for case '{chosen}'...")
        self._set_running(True)
        self._worker = threading.Thread(target=self._run_verify_worker, args=(chosen,), daemon=True)
        self._worker.start()

    def _on_open_html(self) -> None:
        if self._summary is not None and self._summary.html_report is not None:
            _open_in_file_manager(self._summary.html_report)

    def _on_open_folder(self) -> None:
        if self._summary is not None and self._summary.output_dir.parts:
            _open_in_file_manager(self._summary.output_dir)

    def _on_finding_double_clicked(self, _event: object) -> None:
        selection = self.findings.selection()
        if not selection or self._summary is None:
            return
        row = self._summary.findings[self.findings.index(selection[0])]
        lines = [
            f"Device:      {row.device}",
            f"Session:     {row.session_start} -> {row.session_end}",
            f"Boundaries:  {row.boundaries}",
            f"Risk score:  {row.total_score}",
            f"Confidence:  {row.confidence}",
            "",
            f"Why this level: {row.reason}",
            "",
            "Score breakdown:",
        ]
        lines.extend(f"  {line}" for line in row.contributions)
        if not row.contributions:
            lines.append("  No scoring rule fired for this session.")
        messagebox.showinfo("Finding details", "\n".join(lines), parent=self.root)

    # ------------------------------------------------------------------
    # Worker threads (never touch widgets here)
    # ------------------------------------------------------------------

    def _run_analysis_worker(
        self, *, mode: str, evidence_dir: str, case_dir: str, case_id: str, examiner: str
    ) -> None:
        try:
            result = controller.run_analysis(
                mode=mode,
                evidence_dir=evidence_dir,
                case_dir=case_dir,
                case_id=case_id,
                examiner=examiner,
                progress=lambda message: self._queue.put(("log", message)),
            )
        except (ExfilTrackError, OSError) as exc:
            self._queue.put(("error", str(exc)))
        except Exception as exc:  # unexpected; still no raw traceback for the analyst
            self._queue.put(("error", f"Unexpected error: {exc}"))
        else:
            self._queue.put(("result", controller.summarize_result(result)))
        finally:
            self._queue.put(("finished", ""))

    def _run_verify_worker(self, case_dir: str) -> None:
        try:
            summary = controller.verify_case(case_dir)
        except (ExfilTrackError, OSError) as exc:
            self._queue.put(("error", str(exc)))
        except Exception as exc:  # unexpected; still no raw traceback for the analyst
            self._queue.put(("error", f"Unexpected error: {exc}"))
        else:
            self._queue.put(("verify-result", summary))
        finally:
            self._queue.put(("finished", ""))

    # ------------------------------------------------------------------
    # Queue draining and result display (main thread)
    # ------------------------------------------------------------------

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "log":
                    self._append_log(payload)
                elif kind == "result":
                    self._show_summary(payload)
                elif kind == "verify-result":
                    self._show_verification(payload)
                elif kind == "error":
                    self._show_error(payload)
                elif kind == "finished":
                    self._set_running(False)
        except queue.Empty:
            pass
        self.root.after(_QUEUE_POLL_MS, self._poll_queue)

    def _show_summary(self, summary: AnalysisSummary) -> None:
        self._summary = summary
        for row in summary.findings:
            self.findings.insert(
                "",
                tk.END,
                values=(
                    row.device,
                    row.session_start,
                    row.total_score,
                    row.confidence,
                    row.boundaries,
                ),
            )
        counts = ", ".join(f"{label}: {count}" for label, count in summary.confidence_counts)
        self.summary_var.set(
            f"Case {summary.case_id} (examiner {summary.examiner}) - "
            f"artifacts: {summary.artifacts}, events: {summary.events}, "
            f"sessions: {summary.sessions}, findings: {len(summary.findings)}"
            + (f" ({counts})" if counts else "")
        )
        self.integrity_var.set(f"Evidence integrity: {summary.integrity_verdict}")
        if summary.parser_errors:
            self._append_log(
                f"WARNING: {len(summary.parser_errors)} artifact(s) could not be parsed; "
                "results are PARTIAL."
            )
            for line in summary.parser_errors:
                self._append_log(f"  parser error: {line}")
            messagebox.showwarning(
                "Partial analysis",
                f"{len(summary.parser_errors)} artifact(s) could not be parsed. "
                "See the log pane for details.",
                parent=self.root,
            )
        self._append_log("Reports written:")
        for name, path in summary.report_paths:
            self._append_log(f"  {name}: {path}")
        if summary.html_report is not None:
            self.open_html_button.configure(state=tk.NORMAL)
        if summary.output_dir.parts:
            self.open_folder_button.configure(state=tk.NORMAL)
        self.status_var.set("Analysis complete.")

    def _show_verification(self, summary: VerificationSummary) -> None:
        if summary.verified:
            message = (
                f"INTEGRITY VERIFIED: all {summary.total} artifact digest(s) " "match the manifest."
            )
            self._append_log(message)
            messagebox.showinfo("Verify case", message, parent=self.root)
        else:
            message = (
                f"INTEGRITY FAILED: {len(summary.failures)} of {summary.total} "
                "artifact(s) changed or missing."
            )
            self._append_log(message)
            for line in summary.failures:
                self._append_log(f"  - {line}")
            messagebox.showwarning(
                "Verify case", message + "\nSee the log pane for details.", parent=self.root
            )
        self.status_var.set("Verification complete.")

    def _show_error(self, message: str) -> None:
        self._append_log(f"error: {message}")
        self.status_var.set("Failed.")
        messagebox.showerror(f"{__tool_name__}", message, parent=self.root)

    # ------------------------------------------------------------------
    # Small UI helpers
    # ------------------------------------------------------------------

    def _append_log(self, message: str) -> None:
        self.log.configure(state=tk.NORMAL)
        self.log.insert(tk.END, message + "\n")
        self.log.see(tk.END)
        self.log.configure(state=tk.DISABLED)

    def _clear_results(self) -> None:
        self._summary = None
        self.findings.delete(*self.findings.get_children())
        self.summary_var.set("No analysis run yet.")
        self.integrity_var.set("")
        self.open_html_button.configure(state=tk.DISABLED)
        self.open_folder_button.configure(state=tk.DISABLED)

    def _set_running(self, running: bool) -> None:
        state = tk.DISABLED if running else tk.NORMAL
        self.run_button.configure(state=state)
        self.verify_button.configure(state=state)
        if running:
            self.status_var.set("Working...")
            self.progress_bar.start(12)
        else:
            self.progress_bar.stop()


def main() -> int:
    """Launch the GUI. Entry point declared in ``pyproject.toml``."""
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(
            f"error: cannot start the graphical interface ({exc}); "
            "a desktop session is required.",
            file=sys.stderr,
        )
        return 1
    ExfilTrackApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
