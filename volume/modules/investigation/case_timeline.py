from volume.core.module_base import BaseModule


class CaseTimeline(BaseModule):
    @property
    def id(self):
        return "case_timeline"

    @property
    def label(self):
        return "Case Timeline"

    @property
    def category(self):
        return "INVESTIGATION"

    @property
    def description(self):
        return "Chronological view of every finding in the open case"

    @property
    def order(self):
        return 20

    @property
    def credit_cost(self):
        return 0

    def run(self, case, **kwargs):
        if case is None:
            return self.result(rows=[("Error", "No case is open")], status="error")

        timeline = case.timeline()
        stats = case.stats()
        rows = [
            ("Case", case.name),
            ("Findings", str(stats["findings"])),
            ("Entities", str(stats["entities"])),
            ("First finding", stats.get("first") or "-"),
            ("Last finding", stats.get("last") or "-"),
            ("Modules used", ", ".join(f"{k}×{v}" for k, v in stats["modules"].items()) or "-"),
        ]
        for entry in timeline:
            rows.append(
                (
                    (entry["at"] or "")[:19],
                    f"{entry['module']} · {entry['title']} · {entry['query'] or '-'} "
                    f"[{entry['confidence'] or '-'}]",
                )
            )
        if not timeline:
            rows.append(("Result", "No findings yet. Run a module to start the timeline."))
        return self.result(
            title=f"Timeline: {case.name}",
            source="case database",
            confidence="high",
            rows=rows,
            findings=stats["findings"],
        )

    def pivots(self, result):
        return []
