import csv
import datetime
import html
import json
import re
from xml.sax.saxutils import escape

from volume.core import config

FORMATS = {
    "1": ("json", "JSON"),
    "2": ("txt", "TXT"),
    "3": ("csv", "CSV"),
    "4": ("md", "Markdown"),
    "5": ("html", "HTML report"),
    "6": ("pdf", "PDF"),
}


def _safe_name(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", name or "case").strip("_")
    return slug[:60] or "case"


def _finding_rows(finding: dict) -> list:
    try:
        result = json.loads(finding.get("result_json") or "{}")
    except Exception:
        result = {}
    rows = result.get("rows") or []
    parsed = []
    for row in rows:
        try:
            key, value = row
        except Exception:
            key, value = "value", row
        parsed.append((str(key), str(value)))
    return parsed


def _case_payload(case) -> dict:
    findings = case.get_findings()
    return {
        "case": {
            "id": case.id,
            "name": case.name,
            "analyst": case.analyst,
            "notes": getattr(case, "notes", ""),
            "tags": getattr(case, "tags", ""),
        },
        "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "findings": [
            {
                "id": f["id"],
                "module": f["module"],
                "title": f["title"],
                "query": f["query"],
                "source": f["source"],
                "confidence": f["confidence"],
                "retrieved_at": f["retrieved_at"],
                "rows": [{"key": k, "value": v} for k, v in _finding_rows(f)],
            }
            for f in findings
        ],
    }


def _export_json(case, path):
    path.write_text(json.dumps(_case_payload(case), indent=2), encoding="utf-8")


def _export_txt(case, path):
    findings = case.get_findings()
    lines = [
        "VOLUME CASE EXPORT",
        "=" * 60,
        f"Case:     {case.name}",
        f"Case ID:  {case.id}",
        f"Analyst:  {case.analyst}",
        f"Findings: {len(findings)}",
        f"Exported: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]
    for idx, f in enumerate(findings, 1):
        lines.extend([
            "-" * 60,
            f"[{idx}] {f['module']} :: {f['title']}",
            f"Query:      {f['query'] or '-'}",
            f"Source:     {f['source'] or '-'}",
            f"Confidence: {f['confidence'] or '-'}",
            f"Retrieved:  {f['retrieved_at'] or '-'}",
            "",
        ])
        for key, value in _finding_rows(f):
            lines.append(f"  {key}: {value}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def _export_csv(case, path):
    findings = case.get_findings()
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "case_id", "case_name", "finding_id", "module", "title", "query",
            "source", "confidence", "retrieved_at", "key", "value",
        ])
        for f in findings:
            rows = _finding_rows(f)
            if not rows:
                rows = [("", "")]
            for key, value in rows:
                writer.writerow([
                    case.id, case.name, f["id"], f["module"], f["title"],
                    f["query"], f["source"], f["confidence"],
                    f["retrieved_at"], key, value,
                ])


def _export_md(case, path):
    findings = case.get_findings()
    lines = [
        f"# {case.name}",
        "",
        f"- **Case ID:** {case.id}",
        f"- **Analyst:** {case.analyst}",
        f"- **Findings:** {len(findings)}",
        f"- **Exported:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]
    if getattr(case, "notes", ""):
        lines.extend([f"> {case.notes}", ""])
    for f in findings:
        lines.extend([
            f"## {f['module']} — {f['title']}",
            "",
            f"- **Query:** {f['query'] or '-'}",
            f"- **Source:** {f['source'] or '-'}",
            f"- **Confidence:** {f['confidence'] or '-'}",
            f"- **Retrieved:** {f['retrieved_at'] or '-'}",
            "",
        ])
        for key, value in _finding_rows(f):
            lines.append(f"- **{key}:** {value}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def _export_html(case, path):
    findings = case.get_findings()
    stats = case.stats()
    cards = [
        ("Findings", stats["findings"]),
        ("Entities", stats["entities"]),
        ("Modules", len(stats["modules"])),
        ("Analyst", case.analyst or "-"),
    ]
    cards_html = "".join(
        f'<div class="card"><span>{html.escape(str(label))}</span>'
        f'<strong>{html.escape(str(value))}</strong></div>'
        for label, value in cards
    )
    sections = []
    for idx, f in enumerate(findings, 1):
        rows = "".join(
            f"<tr><th>{html.escape(key)}</th><td>{html.escape(value)}</td></tr>"
            for key, value in _finding_rows(f)
        ) or '<tr><td colspan="2" class="muted">No structured rows.</td></tr>'
        sections.append(
            f"""
            <section class="finding">
              <h2>{idx}. {html.escape(f['module'])} <span class="muted">::</span> {html.escape(f['title'])}</h2>
              <div class="meta">
                <span><b>Query</b> {html.escape(f['query'] or '-')}</span>
                <span><b>Source</b> {html.escape(f['source'] or '-')}</span>
                <span><b>Confidence</b> {html.escape(f['confidence'] or '-')}</span>
                <span><b>Retrieved</b> {html.escape(f['retrieved_at'] or '-')}</span>
              </div>
              <table>{rows}</table>
            </section>
            """
        )
    if not sections:
        sections.append('<p class="muted">No findings in this case yet.</p>')

    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VOLUME — {html.escape(case.name or 'Case')}</title>
<style>
  :root {{ --bg:#07110c; --panel:#0d1b13; --line:#1f4d35; --fg:#d7ffe9; --dim:#7fae94; --accent:#00ff88; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:32px; background:radial-gradient(circle at top,#0b2418,var(--bg) 55%);
         color:var(--fg); font:15px/1.55 "Segoe UI",system-ui,sans-serif; }}
  header {{ border:1px solid var(--line); border-radius:14px; padding:22px 26px; background:var(--panel);
            box-shadow:0 0 40px rgba(0,255,136,.08); }}
  h1 {{ margin:0 0 4px; letter-spacing:.35em; font-size:22px; color:var(--accent); }}
  h2 {{ font-size:17px; margin:0 0 10px; }}
  .muted {{ color:var(--dim); }}
  .sub {{ color:var(--dim); margin:0; }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin:22px 0; }}
  .card {{ border:1px solid var(--line); border-radius:12px; background:var(--panel); padding:14px 16px; }}
  .card span {{ display:block; color:var(--dim); font-size:12px; text-transform:uppercase; letter-spacing:.12em; }}
  .card strong {{ font-size:22px; color:var(--accent); }}
  .finding {{ border:1px solid var(--line); border-radius:12px; background:var(--panel); padding:18px 20px; margin:16px 0; }}
  .meta {{ display:flex; flex-wrap:wrap; gap:8px 22px; color:var(--dim); font-size:13px; margin-bottom:12px; }}
  .meta b {{ color:var(--fg); font-weight:600; margin-right:4px; }}
  table {{ width:100%; border-collapse:collapse; font-size:14px; }}
  th, td {{ text-align:left; padding:7px 10px; border-top:1px solid rgba(31,77,53,.65); vertical-align:top; word-break:break-word; }}
  th {{ width:30%; color:var(--dim); font-weight:600; }}
  footer {{ margin-top:26px; color:var(--dim); font-size:12px; text-align:center; }}
</style>
</head>
<body>
  <header>
    <h1>VOLUME</h1>
    <p class="sub">Case report · {html.escape(case.name or 'Untitled')} · exported {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
  </header>
  <div class="cards">{cards_html}</div>
  {''.join(sections)}
  <footer>Generated by VOLUME. Validate findings before acting on them.</footer>
</body>
</html>"""
    path.write_text(document, encoding="utf-8")


def _export_pdf(case, path):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(
        str(path), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"Volume Case - {case.name}",
    )
    story = [
        Paragraph(escape(f"Volume Case: {case.name}"), styles["Title"]),
        Paragraph(
            escape(
                f"Case ID: {case.id} &nbsp;&nbsp; Analyst: {case.analyst} "
                f"&nbsp;&nbsp; Findings: {len(case.get_findings())}"
            ),
            styles["BodyText"],
        ),
        Spacer(1, 6 * mm),
    ]

    findings = case.get_findings()
    if not findings:
        story.append(Paragraph("No findings in this case yet.", styles["BodyText"]))

    for idx, f in enumerate(findings, 1):
        story.append(Paragraph(
            escape(f"{idx}. {f['module']} - {f['title']}"),
            styles["Heading2"],
        ))
        meta = (
            f"Query: {f['query'] or '-'} &nbsp;&nbsp; "
            f"Source: {f['source'] or '-'} &nbsp;&nbsp; "
            f"Confidence: {f['confidence'] or '-'}<br/>"
            f"Retrieved: {f['retrieved_at'] or '-'}"
        )
        story.append(Paragraph(escape(meta).replace("&amp;nbsp;", "&nbsp;"), styles["BodyText"]))
        story.append(Spacer(1, 2 * mm))

        rows = _finding_rows(f) or [("-", "-")]
        table_data = [[
            Paragraph("<b>Key</b>", styles["BodyText"]),
            Paragraph("<b>Value</b>", styles["BodyText"]),
        ]]
        for key, value in rows:
            table_data.append([
                Paragraph(escape(key), styles["BodyText"]),
                Paragraph(escape(value), styles["BodyText"]),
            ])
        table = Table(table_data, colWidths=[42 * mm, 112 * mm], repeatRows=1)
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#999999")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(table)
        story.append(Spacer(1, 6 * mm))

    doc.build(story)


_EXPORTERS = {
    "json": _export_json,
    "txt": _export_txt,
    "csv": _export_csv,
    "md": _export_md,
    "html": _export_html,
    "pdf": _export_pdf,
}


def export_case(case, fmt: str):
    fmt = fmt.lower()
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = config.EXPORT_DIR / f"{_safe_name(case.name)}_{stamp}.{fmt}"
    if fmt not in _EXPORTERS:
        raise ValueError(f"Unsupported export format: {fmt}")
    _EXPORTERS[fmt](case, path)
    return path
