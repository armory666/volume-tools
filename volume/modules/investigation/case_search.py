from volume.core.module_base import BaseModule


class CaseSearch(BaseModule):
    @property
    def id(self):
        return "case_search"

    @property
    def label(self):
        return "Case Search"

    @property
    def category(self):
        return "INVESTIGATION"

    @property
    def description(self):
        return "Full-text search across the open case's findings, titles and entities"

    @property
    def order(self):
        return 35

    @property
    def credit_cost(self):
        return 0

    @property
    def inputs(self):
        return ["keyword"]

    @property
    def optional_inputs(self):
        return {"limit": "50"}

    @property
    def input_prompts(self):
        return {
            "keyword": "Search term (email, domain, module, CVE, ...)",
            "limit": "Maximum matches to show",
        }

    def run(self, case, **kwargs):
        if case is None:
            return self.result(rows=[("Error", "No case is open")], status="error")

        keyword = str(kwargs.get("keyword") or "").strip()
        if not keyword:
            return self.result(rows=[("Error", "No keyword provided")], status="error")
        try:
            limit = max(1, min(200, int(kwargs.get("limit") or 50)))
        except (TypeError, ValueError):
            limit = 50

        like = f"%{keyword}%"
        findings = case.conn.execute(
            "SELECT id, module, title, query, source, confidence, retrieved_at "
            "FROM findings WHERE case_id=? AND ("
            "module LIKE ? OR title LIKE ? OR query LIKE ? OR source LIKE ? "
            "OR confidence LIKE ? OR result_json LIKE ?) "
            "ORDER BY id DESC LIMIT ?",
            (case.id, like, like, like, like, like, like, limit),
        ).fetchall()

        entities = case.conn.execute(
            "SELECT e.type, e.value, COUNT(*) AS hits FROM entities e "
            "JOIN findings f ON f.id=e.finding_id "
            "WHERE f.case_id=? AND e.value LIKE ? "
            "GROUP BY e.type, e.value ORDER BY hits DESC LIMIT ?",
            (case.id, like, limit),
        ).fetchall()

        rows = [
            ("Case", case.name),
            ("Keyword", keyword),
            ("Findings matched", str(len(findings))),
            ("Entities matched", str(len(entities))),
        ]
        for finding in findings:
            rows.append(
                (
                    f"#{finding['id']} {finding['module']}",
                    f"{finding['title']} · {finding['query'] or '-'} "
                    f"[{finding['confidence'] or '-'}] · {(finding['retrieved_at'] or '')[:19]}",
                )
            )
        for entity in entities:
            rows.append(
                (
                    f"{entity['type']}",
                    f"{entity['value']}  ({entity['hits']} hit(s))",
                )
            )

        if not findings and not entities:
            rows.append(("Result", "No matches in this case."))
            return self.result(
                title=f"Case Search: {keyword}",
                source="case database",
                confidence="high",
                rows=rows,
                status="not_found",
            )

        return self.result(
            title=f"Case Search: {keyword}",
            source="case database",
            confidence="high",
            rows=rows,
            findings=len(findings),
            entities=len(entities),
        )

    def pivots(self, result):
        return []
