from __future__ import annotations

import queue
import re
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from ai.ollama_client import DEFAULT_MODEL, OllamaClient, OllamaError
from reports.exporter import export_json, export_markdown
from scanner.engine import scan_project
from scanner.models import Finding, ScanResult, Severity
from ui.finding_details import FindingDetails


def _report_dialog_options(
    result: ScanResult,
    format_name: str,
    project_root: Path | None = None,
) -> dict[str, object]:
    extension = ".json" if format_name == "json" else ".md"
    reports_dir = (project_root or Path(__file__).resolve().parents[1]) / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    project_name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", result.project_name)
    project_name = project_name.strip(" .")[:100]
    if not project_name:
        project_name = "project"
    filename = f"securelocal-{project_name}-report"
    candidate = reports_dir / f"{filename}{extension}"
    suffix = 2
    while candidate.exists():
        candidate = reports_dir / f"{filename}-{suffix}{extension}"
        suffix += 1

    return {
        "initialdir": str(reports_dir),
        "initialfile": candidate.name,
        "defaultextension": extension,
        "filetypes": [(f"{format_name.upper()} report", f"*{extension}")],
        "confirmoverwrite": True,
    }


class SecureLocalApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("SecureLocal AI — Code Security Auditor")
        self.root.geometry("1120x780")
        self.root.minsize(860, 600)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.root.configure(bg="#F3F6FB")
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.result: ScanResult | None = None
        self.findings_by_id: dict[str, Finding] = {}
        self.summary_cards: dict[str, tuple[ttk.Label, tk.StringVar]] = {}
        self._configure_style()
        self._build_ui()
        self.root.after(100, self._process_events)

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", font=("Segoe UI", 10), background="#F3F6FB", foreground="#0F172A")
        style.configure("Header.TFrame", background="#112A46")
        style.configure("Header.TLabel", font=("Segoe UI", 20, "bold"), background="#112A46", foreground="#FFFFFF")
        style.configure("Subtitle.TLabel", font=("Segoe UI", 10), background="#112A46", foreground="#D7E2F3")
        style.configure("Section.TLabel", font=("Segoe UI", 10, "bold"), background="#F3F6FB", foreground="#1E293B")
        style.configure("Section.TLabelframe", background="#F3F6FB", bordercolor="#D4DDEB", lightcolor="#D4DDEB", darkcolor="#D4DDEB")
        style.configure("Section.TLabelframe.Label", font=("Segoe UI", 10, "bold"), background="#F3F6FB", foreground="#1E293B")
        style.configure("Card.TFrame", background="#FFFFFF", relief="solid", borderwidth=1)
        style.configure("SummaryLabel.TLabel", font=("Segoe UI", 9, "bold"), background="#FFFFFF", foreground="#475467")
        style.configure("SummaryValue.TLabel", font=("Segoe UI", 18, "bold"), background="#FFFFFF", foreground="#0F172A")
        style.configure("Toolbar.TFrame", background="#EEF3FA")
        style.configure("Toolbar.TLabel", background="#EEF3FA", foreground="#475467", font=("Segoe UI", 9, "bold"))
        style.configure("Status.TLabel", background="#F3F6FB", foreground="#475467", wraplength=1100)
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), background="#2F6FED", foreground="#FFFFFF")
        style.map("Primary.TButton", background=[("active", "#255ad6"), ("pressed", "#1f4bb7")], foreground=[("disabled", "#E2E8F0")])
        style.configure("Secondary.TButton", background="#FFFFFF", foreground="#0F172A")
        style.map("Secondary.TButton", background=[("active", "#EEF3FA"), ("pressed", "#E2E8F0")])
        style.configure("Treeview", rowheight=26, background="#FFFFFF", fieldbackground="#FFFFFF", borderwidth=0)
        style.map("Treeview", background=[("selected", "#D9E7FF")], foreground=[("selected", "#0F172A")])
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background="#E2E8F0", foreground="#0F172A")
        style.map("Treeview.Heading", background=[("active", "#D9E7FF")])
        style.configure("Panel.TFrame", background="#FFFFFF")

    def _build_ui(self) -> None:
        container = ttk.Frame(self.root, padding=16, style="Panel.TFrame")
        container.grid(row=0, column=0, sticky="nsew")
        container.columnconfigure(0, weight=1)
        container.rowconfigure(5, weight=1)

        header = ttk.Frame(container, style="Header.TFrame", padding=(18, 16))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="SecureLocal AI", style="Header.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            header,
            text="Offline-first Python code security checks for local review and remediation.",
            style="Subtitle.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        folder_frame = ttk.LabelFrame(container, text="Project selection", padding=12)
        folder_frame.grid(row=1, column=0, sticky="ew", pady=(16, 10))
        folder_frame.columnconfigure(0, weight=1)
        self.project_path = tk.StringVar()
        ttk.Entry(folder_frame, textvariable=self.project_path, width=60).grid(row=0, column=0, sticky="ew", padx=(0, 10))
        ttk.Button(
            folder_frame,
            text="Choose folder…",
            command=self._choose_folder,
            style="Secondary.TButton",
        ).grid(row=0, column=1, padx=(0, 10))
        self.scan_button = ttk.Button(
            folder_frame,
            text="Scan project",
            command=self._start_scan,
            style="Primary.TButton",
        )
        self.scan_button.grid(row=0, column=2)

        self.summary_cards_frame = ttk.Frame(container, padding=(0, 0, 0, 8))
        self.summary_cards_frame.grid(row=2, column=0, sticky="ew")
        self.summary_cards_frame.columnconfigure(0, weight=1)
        self.summary_cards_frame.columnconfigure(1, weight=1)
        self.summary_cards_frame.columnconfigure(2, weight=1)
        self.summary_cards_frame.columnconfigure(3, weight=1)
        self.summary_cards_frame.columnconfigure(4, weight=1)
        self._build_summary_cards()

        toolbar = ttk.Frame(container, style="Toolbar.TFrame", padding=(12, 10))
        toolbar.grid(row=3, column=0, sticky="ew", pady=(0, 10))
        toolbar.columnconfigure(4, weight=1)
        ttk.Label(toolbar, text="Severity", style="Toolbar.TLabel").grid(row=0, column=0, sticky="w")
        self.severity_filter = tk.StringVar(value="All")
        self.severity_combo = ttk.Combobox(
            toolbar,
            textvariable=self.severity_filter,
            state="readonly",
            values=("All", *(severity.value for severity in Severity)),
            width=12,
        )
        self.severity_combo.grid(row=0, column=1, sticky="w", padx=(6, 18))
        self.severity_combo.bind("<<ComboboxSelected>>", self._apply_filters)
        ttk.Label(toolbar, text="Search", style="Toolbar.TLabel").grid(row=0, column=2, sticky="w")
        self.search_text = tk.StringVar()
        search = ttk.Entry(toolbar, textvariable=self.search_text, width=30)
        search.grid(row=0, column=3, sticky="ew", padx=(6, 12))
        self.search_text.trace_add("write", self._apply_filters)
        self.summary = ttk.Label(toolbar, text="Choose a project folder to begin.", style="Toolbar.TLabel")
        self.summary.grid(row=0, column=4, sticky="e")

        actions = ttk.Frame(container, padding=(0, 0, 0, 8))
        actions.grid(row=4, column=0, sticky="ew")
        self.ai_model = tk.StringVar(value=DEFAULT_MODEL)
        ttk.Label(actions, text="Local model", style="Section.TLabel").pack(side="left")
        ttk.Entry(actions, textvariable=self.ai_model, width=22).pack(side="left", padx=(6, 8))
        self.explain_button = ttk.Button(
            actions,
            text="Explain selected with local AI",
            command=self._explain_selected,
            state="disabled",
            style="Primary.TButton",
        )
        self.explain_button.pack(side="left", padx=(0, 12))
        self.export_json_button = ttk.Button(
            actions,
            text="Export JSON…",
            command=self._export_json,
            state="disabled",
            style="Secondary.TButton",
        )
        self.export_json_button.pack(side="right", padx=(8, 0))
        self.export_md_button = ttk.Button(
            actions,
            text="Export Markdown…",
            command=self._export_markdown,
            state="disabled",
            style="Secondary.TButton",
        )
        self.export_md_button.pack(side="right")

        content = ttk.Panedwindow(container, orient="vertical")
        content.grid(row=5, column=0, sticky="nsew")
        table_frame = ttk.Frame(content, style="Panel.TFrame")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        columns = ("severity", "rule", "file", "line", "title")
        self.table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
            height=10,
        )
        self.table.tag_configure("oddrow", background="#F8FAFC")
        self.table.tag_configure("Critical", foreground="#B42318")
        self.table.tag_configure("High", foreground="#D97706")
        self.table.tag_configure("Medium", foreground="#AC6B0C")
        self.table.tag_configure("Low", foreground="#2F6FED")
        self.table.tag_configure("Info", foreground="#475467")
        for column, heading, width in (
            ("severity", "Severity", 100),
            ("rule", "Rule", 86),
            ("file", "File", 260),
            ("line", "Line", 62),
            ("title", "Finding", 360),
        ):
            self.table.heading(column, text=heading)
            self.table.column(column, width=width, anchor="w")
        self.table.grid(row=0, column=0, sticky="nsew")
        self.table.bind("<<TreeviewSelect>>", self._selection_changed)
        vertical = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        vertical.grid(row=0, column=1, sticky="ns")
        self.table.configure(yscrollcommand=vertical.set)
        horizontal = ttk.Scrollbar(table_frame, orient="horizontal", command=self.table.xview)
        horizontal.grid(row=1, column=0, sticky="ew")
        self.table.configure(xscrollcommand=horizontal.set)
        self.details = FindingDetails(content)
        content.add(table_frame, weight=4)
        content.add(self.details, weight=1)

        self.status = tk.StringVar(value="Scanning uses local deterministic rules. Source files are not changed or uploaded.")
        ttk.Label(container, textvariable=self.status, style="Status.TLabel").grid(row=6, column=0, sticky="ew", pady=(8, 0))

    def _build_summary_cards(self) -> None:
        self.summary_cards = {}
        labels = [
            ("Total findings", "total"),
            ("High", "high"),
            ("Medium", "medium"),
            ("Low", "low"),
            ("Info", "info"),
        ]
        for index, (label_text, key) in enumerate(labels):
            card = ttk.Frame(self.summary_cards_frame, padding=(12, 10), style="Card.TFrame")
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 8, 0))
            if key == "info":
                card.grid_remove()
            ttk.Label(card, text=label_text, style="SummaryLabel.TLabel").pack(anchor="w")
            value = tk.StringVar(value="0")
            ttk.Label(card, textvariable=value, style="SummaryValue.TLabel").pack(anchor="w", pady=(4, 0))
            self.summary_cards[key] = (card, value)
        self._update_summary_cards(None)

    def _update_summary_cards(self, result: ScanResult | None) -> None:
        cards = {
            "total": "0",
            "high": "0",
            "medium": "0",
            "low": "0",
            "info": "0",
        }
        if result is not None:
            counts = result.counts_by_severity
            cards["total"] = str(len(result.findings))
            cards["high"] = str(counts["High"])
            cards["medium"] = str(counts["Medium"])
            cards["low"] = str(counts["Low"])
            cards["info"] = str(counts["Info"])
        for key, value in cards.items():
            if key in self.summary_cards:
                self.summary_cards[key][1].set(value)
        info_card = self.summary_cards.get("info")
        if info_card is not None:
            card, _ = info_card
            if cards["info"] == "0":
                card.grid_remove()
            else:
                card.grid(row=0, column=4, sticky="nsew", padx=(8, 0))

    def _choose_folder(self) -> None:
        selected = filedialog.askdirectory(title="Choose a Python project folder")
        if selected:
            self.project_path.set(selected)

    def _start_scan(self) -> None:
        selected = self.project_path.get().strip()
        if not selected or not Path(selected).is_dir():
            messagebox.showerror("Choose a project", "Select an existing project folder first.")
            return
        self.scan_button.configure(state="disabled")
        self.status.set("Scanning Python files locally…")
        self.summary.configure(text="Scan in progress")
        self._clear_findings()
        thread = threading.Thread(target=self._scan_worker, args=(selected,), daemon=True)
        thread.start()

    def _scan_worker(self, selected: str) -> None:
        try:
            self.events.put(("scan", scan_project(selected)))
        except (OSError, ValueError, RecursionError) as error:
            self.events.put(("error", str(error)))

    def _process_events(self) -> None:
        try:
            while True:
                event, payload = self.events.get_nowait()
                if event == "scan":
                    if isinstance(payload, ScanResult):
                        self._show_result(payload)
                elif event == "explanation":
                    if isinstance(payload, tuple) and len(payload) == 2:
                        self._show_explanation(payload)
                elif event == "error":
                    self._handle_error(payload)
        except queue.Empty:
            pass
        self.root.after(100, self._process_events)

    def _show_result(self, result: ScanResult) -> None:
        self.result = result
        self.scan_button.configure(state="normal")
        self.export_json_button.configure(state="normal")
        self.export_md_button.configure(state="normal")
        self._populate_findings()
        self._update_summary_cards(result)
        counts = result.counts_by_severity
        summary_bits = [
            f"{result.files_scanned} files scanned",
            f"{counts['Critical']} critical",
            f"{counts['High']} high",
            f"{counts['Medium']} medium",
            f"{counts['Low']} low",
        ]
        if counts["Info"]:
            summary_bits.append(f"{counts['Info']} info")
        self.summary.configure(text=" · ".join(summary_bits))
        skipped_note = f" {len(result.skipped_files)} file(s) skipped." if result.skipped_files else ""
        limit_note = " A safety limit was reached; this scan may be incomplete." if result.truncated else ""
        self.status.set(
            f"Scan complete. Findings are deterministic; no files were changed or uploaded."
            f"{skipped_note}{limit_note}"
        )

    def _populate_findings(self) -> None:
        self._clear_table_rows()
        if self.result is None:
            return
        for index, finding in enumerate(self.result.findings):
            item_id = f"finding-{index}"
            self.findings_by_id[item_id] = finding
            tags = (finding.severity.value,)
            if index % 2 == 1:
                tags = tags + ("oddrow",)
            self.table.insert(
                "",
                "end",
                iid=item_id,
                tags=tags,
                values=(
                    finding.severity.value,
                    finding.rule_id,
                    finding.file_path,
                    finding.line,
                    finding.title,
                ),
            )
        self._apply_filters()

    def _clear_table_rows(self) -> None:
        item_ids = tuple(dict.fromkeys((*self.findings_by_id, *self.table.get_children())))
        for item_id in item_ids:
            if self.table.exists(item_id):
                self.table.delete(item_id)
        self.findings_by_id.clear()

    def _apply_filters(self, *_: object) -> None:
        query = self.search_text.get().strip().casefold()
        severity = self.severity_filter.get()
        for item_id, finding in self.findings_by_id.items():
            matches_severity = severity == "All" or finding.severity.value == severity
            haystack = " ".join((finding.rule_id, finding.title, finding.file_path, finding.evidence)).casefold()
            visible = matches_severity and query in haystack
            if visible and not self.table.exists(item_id):
                self.table.reattach(item_id, "", "end")
            elif not visible and self.table.exists(item_id):
                self.table.detach(item_id)

    def _selection_changed(self, _event: tk.Event) -> None:
        selected = self.table.selection()
        finding = self.findings_by_id.get(selected[0]) if selected else None
        self.details.show_finding(finding)
        self.explain_button.configure(state="normal" if finding else "disabled")

    def _clear_findings(self) -> None:
        self.result = None
        self._clear_table_rows()
        self._update_summary_cards(None)
        self.summary.configure(text="Choose a project folder to begin.")
        self.details.show_finding(None)
        self.explain_button.configure(state="disabled")
        self.export_json_button.configure(state="disabled")
        self.export_md_button.configure(state="disabled")

    def _handle_error(self, payload: object) -> None:
        self.scan_button.configure(state="normal")
        self._update_summary_cards(None)
        self.summary.configure(text="Scan could not be completed.")
        self.status.set("The operation could not be completed.")
        messagebox.showerror("SecureLocal AI", str(payload))

    def _explain_selected(self) -> None:
        selected = self.table.selection()
        if not selected:
            return
        finding = self.findings_by_id[selected[0]]
        model = self.ai_model.get().strip()
        self.explain_button.configure(state="disabled")
        self.status.set("Checking the local Ollama service and installed model…")
        thread = threading.Thread(target=self._explanation_worker, args=(finding, model), daemon=True)
        thread.start()

    def _explanation_worker(self, finding: Finding, model: str) -> None:
        try:
            explanation = OllamaClient().explain_finding(finding, model)
            self.events.put(("explanation", (True, explanation)))
        except OllamaError as error:
            self.events.put(("explanation", (False, str(error))))

    def _show_explanation(self, payload: tuple[bool, str]) -> None:
        success, text = payload
        self.explain_button.configure(state="normal" if self.table.selection() else "disabled")
        if success:
            dialog = tk.Toplevel(self.root)
            dialog.title("Local AI explanation — unverified advice")
            dialog.geometry("620x460")
            dialog.transient(self.root)
            frame = ttk.Frame(dialog, padding=12)
            frame.pack(fill="both", expand=True)
            ttk.Label(
                frame,
                text="AI-generated local explanation. It may be incorrect; confirm findings independently.",
                wraplength=560,
            ).pack(anchor="w", pady=(0, 8))
            content = tk.Text(frame, wrap="word")
            content.pack(fill="both", expand=True)
            content.insert("1.0", text)
            content.configure(state="disabled")
            scrollbar = ttk.Scrollbar(frame, orient="vertical", command=content.yview)
            scrollbar.pack(side="right", fill="y")
            content.configure(yscrollcommand=scrollbar.set)
            ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=(8, 0))
            self.status.set("Local AI explanation received. Deterministic findings were not changed.")
        else:
            self.status.set("Local AI explanation unavailable; built-in remediation remains available.")
            messagebox.showinfo("Local AI unavailable", str(text))

    def _export_json(self) -> None:
        self._export("json")

    def _export_markdown(self) -> None:
        self._export("markdown")

    def _export(self, format_name: str) -> None:
        if self.result is None:
            return
        destination = filedialog.asksaveasfilename(
            title=f"Export {format_name.upper()} report",
            **_report_dialog_options(self.result, format_name),
        )
        if not destination:
            return
        try:
            exporter = export_json if format_name == "json" else export_markdown
            path = exporter(self.result, destination)
        except OSError as error:
            messagebox.showerror("Report export failed", f"The report could not be saved: {error}")
            return
        self.status.set(f"Report exported to {path}. The report contains findings, not source files.")


def run_app() -> None:
    root = tk.Tk()
    SecureLocalApp(root)
    root.mainloop()
