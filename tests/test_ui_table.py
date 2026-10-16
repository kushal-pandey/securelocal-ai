from __future__ import annotations

import unittest

from scanner.models import Finding, ScanResult, Severity
from ui.main_window import SecureLocalApp


class FakeTreeview:
    def __init__(self) -> None:
        self.items: dict[str, tuple[tuple[str, ...], bool]] = {}

    def get_children(self):
        return tuple(item_id for item_id, (_, attached) in self.items.items() if attached)

    def exists(self, item_id: str) -> bool:
        return item_id in self.items

    def delete(self, item_id: str) -> None:
        del self.items[item_id]

    def insert(self, _parent, _index, *, iid, tags, values) -> None:
        if iid in self.items:
            raise RuntimeError(f"Item {iid} already exists")
        self.items[iid] = (tuple(tags), True)

    def detach(self, item_id: str) -> None:
        tags, _ = self.items[item_id]
        self.items[item_id] = (tags, False)

    def reattach(self, item_id: str, _parent, _index) -> None:
        tags, _ = self.items[item_id]
        self.items[item_id] = (tags, True)


class DummyWidget:
    def configure(self, **_kwargs) -> None:
        pass

    def show_finding(self, _finding) -> None:
        pass


def make_result(*findings: Finding) -> ScanResult:
    return ScanResult("project", "2026-01-01T00:00:00+00:00", 1, (), findings, False)


def make_finding(title: str, severity: Severity) -> Finding:
    return Finding(
        "SLA001",
        title,
        severity,
        "example.py",
        1,
        1,
        "redacted evidence",
        "description",
        "remediation",
        "High",
        "limitations",
    )


class FindingsTableTests(unittest.TestCase):
    def make_app(self) -> SecureLocalApp:
        app = SecureLocalApp.__new__(SecureLocalApp)
        app.table = FakeTreeview()
        app.findings_by_id = {}
        app.search_text = type("Search", (), {"get": lambda self: ""})()
        app.severity_filter = type("Filter", (), {"get": lambda self: "All"})()
        app.details = DummyWidget()
        app.explain_button = DummyWidget()
        app.export_json_button = DummyWidget()
        app.export_md_button = DummyWidget()
        app.summary = DummyWidget()
        app.summary_cards = {}
        return app

    def test_repeated_scans_clear_filtered_and_detached_rows(self):
        app = self.make_app()
        app.result = make_result(
            make_finding("High finding", Severity.HIGH),
            make_finding("Low finding", Severity.LOW),
        )
        app._populate_findings()

        app.severity_filter = type("Filter", (), {"get": lambda self: "High"})()
        app._apply_filters()
        self.assertFalse(app.table.items["finding-1"][1])

        app._clear_findings()
        app.result = make_result(
            make_finding("High finding", Severity.HIGH),
            make_finding("Low finding", Severity.LOW),
        )
        app._populate_findings()
        self.assertEqual(set(app.table.items), {"finding-0", "finding-1"})
        self.assertEqual(app.table.items["finding-1"][0], ("Low", "oddrow"))

        app._clear_findings()
        app.result = make_result(make_finding("Different project", Severity.MEDIUM))
        app._populate_findings()
        self.assertEqual(set(app.table.items), {"finding-0"})
        self.assertEqual(app.findings_by_id["finding-0"].title, "Different project")


if __name__ == "__main__":
    unittest.main()
