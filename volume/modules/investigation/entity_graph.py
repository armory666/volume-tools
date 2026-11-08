from collections import defaultdict

from volume.core.module_base import BaseModule


class EntityGraph(BaseModule):
    @property
    def id(self):
        return "entity_graph"

    @property
    def label(self):
        return "Entity Graph / Pivots"

    @property
    def category(self):
        return "INVESTIGATION"

    @property
    def description(self):
        return "Entities, co-occurrence links and cross-module pivots for the case"

    @property
    def order(self):
        return 30

    @property
    def credit_cost(self):
        return 0

    def run(self, case, **kwargs):
        if case is None:
            return self.result(rows=[("Error", "No case is open")], status="error")

        entities = case.entities()
        findings = case.get_findings()
        by_type = defaultdict(list)
        for entity in entities:
            by_type[entity["type"]].append(entity)

        # Co-occurrence: entities that appear in the same finding.
        finding_entities = defaultdict(set)
        conn = case.conn
        for row in conn.execute(
            "SELECT e.finding_id, e.type, e.value FROM entities e "
            "JOIN findings f ON f.id=e.finding_id WHERE f.case_id=?",
            (case.id,),
        ):
            finding_entities[row["finding_id"]].add((row["type"], row["value"]))

        links = defaultdict(int)
        for values in finding_entities.values():
            values = sorted(values)
            for i in range(len(values)):
                for j in range(i + 1, len(values)):
                    links[(values[i], values[j])] += 1

        rows = [
            ("Case", case.name),
            ("Findings", str(len(findings))),
            ("Unique entities", str(len(entities))),
            ("Types", ", ".join(f"{k}:{len(v)}" for k, v in sorted(by_type.items())) or "-"),
        ]
        for ent_type, values in sorted(by_type.items()):
            rows.append((ent_type.upper(), f"{len(values)} unique"))
            for entity in values[:15]:
                rows.append((f"  {entity['value']}", f"{entity['hits']} hit(s)"))

        if links:
            rows.append(("Co-occurrence links", str(len(links))))
            for (left, right), count in sorted(links.items(), key=lambda kv: -kv[1])[:25]:
                rows.append(
                    (
                        f"{left[0]}:{left[1]}",
                        f"↔ {right[0]}:{right[1]}  ({count} shared finding(s))",
                    )
                )
        else:
            rows.append(("Co-occurrence", "not enough linked entities yet"))

        return self.result(
            title=f"Entity Graph: {case.name}",
            source="case entity index",
            confidence="high",
            rows=rows,
            entities=len(entities),
            links=len(links),
        )

    def pivots(self, result):
        return []
