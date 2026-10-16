from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from scanner.models import Finding


class FindingDetails(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, padding=(10, 8), style="Panel.TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        ttk.Label(self, text="Finding details", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.content = tk.Text(
            self,
            height=6,
            wrap="word",
            state="disabled",
            bg="#FFFFFF",
            relief="flat",
            borderwidth=0,
            highlightthickness=0,
            padx=8,
            pady=8,
            spacing1=4,
            spacing2=2,
            spacing3=2,
        )
        self.content.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.content.yview)
        scrollbar.grid(row=1, column=1, sticky="ns", pady=(8, 0))
        self.content.configure(yscrollcommand=scrollbar.set)
        self.content.tag_configure("title", font=("Segoe UI", 12, "bold"), foreground="#0F172A")
        self.content.tag_configure("meta", font=("Segoe UI", 10, "bold"), foreground="#475467")
        self.content.tag_configure("body", font=("Segoe UI", 10), foreground="#1E293B")
        self.content.tag_configure("section", font=("Segoe UI", 10, "bold"), foreground="#1E293B")
        self.content.tag_configure("muted", font=("Segoe UI", 9), foreground="#475467")

    def show_finding(self, finding: Finding | None) -> None:
        self.content.configure(state="normal")
        self.content.delete("1.0", "end")
        if finding is None:
            self.content.insert("end", "Select a finding to view the explanation, evidence, limitations, and remediation.", "body")
            self.content.configure(state="disabled")
            return

        self.content.insert("end", f"{finding.title}\n", "title")
        self.content.insert(
            "end",
            f"Severity: {finding.severity.value} | Rule: {finding.rule_id} | Confidence: {finding.confidence}\n",
            "meta",
        )
        self.content.insert(
            "end",
            f"Location: {finding.file_path}:{finding.line}:{finding.column}\n\n",
            "body",
        )

        sections = [
            ("Why it matters", finding.description),
            ("Redacted evidence", finding.evidence),
            ("Limitations", finding.limitations),
            ("Remediation", finding.remediation),
        ]
        for label, value in sections:
            self.content.insert("end", f"{label}\n", "section")
            self.content.insert("end", f"{value}\n\n", "body")

        self.content.configure(state="disabled")
