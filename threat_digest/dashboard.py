"""Build stable digest aliases and archive pages for generated reports."""

from __future__ import annotations

import html
import re
import shutil
from dataclasses import dataclass
from pathlib import Path


_DIGEST_RE = re.compile(r"^digest_(\d{4}-\d{2}-\d{2})\.html$")


@dataclass(frozen=True)
class DigestReport:
    path: Path
    date: str


def _discover_reports(output_dir: Path) -> list[DigestReport]:
    reports: list[DigestReport] = []
    for path in output_dir.glob("digest_*.html"):
        match = _DIGEST_RE.match(path.name)
        if match:
            reports.append(DigestReport(path=path, date=match.group(1)))
    reports.sort(key=lambda item: item.date, reverse=True)
    return reports


def _build_dashboard_html(reports: list[DigestReport]) -> str:
    latest = reports[0] if reports else None
    latest_link = html.escape(latest.path.name) if latest else "#"
    latest_date = html.escape(latest.date) if latest else "No reports yet"
    report_cards = "\n".join(
        f"""
        <a class="report-row{' report-row--latest' if idx == 0 else ''}" href="{html.escape(report.path.name)}">
          <span>
            <strong>{html.escape(report.date)}</strong>
            <small>{'Latest report' if idx == 0 else 'Archived report'}</small>
          </span>
          <span class="open-label">Open</span>
        </a>
        """
        for idx, report in enumerate(reports)
    )
    if not report_cards:
        report_cards = '<p class="empty">No digest reports have been generated yet.</p>'

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Threat Digest Dashboard</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #08111f;
      --panel: #101b2d;
      --panel-2: #15233a;
      --border: rgba(168, 185, 210, 0.18);
      --text: #edf4ff;
      --muted: #9fb0c8;
      --accent: #5eead4;
      --accent-2: #93c5fd;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: radial-gradient(circle at top left, rgba(94, 234, 212, 0.12), transparent 32rem), var(--bg);
      color: var(--text);
    }}
    main {{
      width: min(1120px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 48px 0;
    }}
    .topbar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      margin-bottom: 36px;
    }}
    .brand {{
      margin: 0;
      font-size: clamp(1.6rem, 4vw, 2.6rem);
      line-height: 1.05;
    }}
    .subtle {{ color: var(--muted); margin: 10px 0 0; max-width: 680px; line-height: 1.6; }}
    .latest {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 24px;
      align-items: center;
      padding: 28px;
      border: 1px solid var(--border);
      background: linear-gradient(135deg, rgba(16, 27, 45, 0.96), rgba(21, 35, 58, 0.94));
      border-radius: 8px;
      box-shadow: 0 24px 70px rgba(0, 0, 0, 0.28);
    }}
    .latest h2 {{ margin: 0 0 8px; font-size: 1.05rem; color: var(--accent); }}
    .latest-date {{ margin: 0; font-size: 2rem; font-weight: 750; }}
    .button {{
      display: inline-flex;
      min-height: 44px;
      align-items: center;
      justify-content: center;
      padding: 0 18px;
      border-radius: 6px;
      color: #04201c;
      background: var(--accent);
      text-decoration: none;
      font-weight: 750;
      white-space: nowrap;
    }}
    section {{ margin-top: 34px; }}
    .section-title {{
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 16px;
      margin-bottom: 14px;
    }}
    .section-title h2 {{ margin: 0; font-size: 1.1rem; }}
    .section-title span {{ color: var(--muted); font-size: 0.92rem; }}
    .report-list {{
      display: grid;
      gap: 10px;
    }}
    .report-row {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 18px;
      padding: 16px 18px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: rgba(16, 27, 45, 0.82);
      color: var(--text);
      text-decoration: none;
    }}
    .report-row:hover {{ border-color: rgba(94, 234, 212, 0.55); background: var(--panel-2); }}
    .report-row small {{ display: block; margin-top: 4px; color: var(--muted); }}
    .report-row--latest strong {{ color: var(--accent); }}
    .open-label {{ color: var(--accent-2); font-weight: 700; }}
    .empty {{ color: var(--muted); }}
    @media (max-width: 720px) {{
      main {{ padding: 28px 0; }}
      .topbar, .latest {{ grid-template-columns: 1fr; display: grid; }}
      .button {{ width: 100%; }}
    }}
  </style>
</head>
<body>
  <main>
    <div class="topbar">
      <div>
        <h1 class="brand">Threat Digest Dashboard</h1>
        <p class="subtle">A stable home for generated threat intelligence reports. Each dated report remains available after the next one is generated.</p>
      </div>
    </div>

    <div class="latest">
      <div>
        <h2>Latest Digest</h2>
        <p class="latest-date">{latest_date}</p>
      </div>
      <a class="button" href="{latest_link}">Open Latest</a>
    </div>

    <section>
      <div class="section-title">
        <h2>Report Archive</h2>
        <span>{len(reports)} report{'s' if len(reports) != 1 else ''}</span>
      </div>
      <div class="report-list">
        {report_cards}
      </div>
    </section>
  </main>
</body>
</html>
"""


def update_digest_dashboard(output_dir: str | Path, latest_html_path: str | Path) -> Path:
    """Write latest aliases plus ``history.html`` for the digest output directory.

    ``index.html`` is the main entry point and should open the current digest.
    ``latest.html`` is kept as a stable compatibility alias. The archive list
    lives at ``history.html``.
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    latest_path = Path(latest_html_path)
    latest_alias = out_dir / "latest.html"
    if latest_path.exists() and latest_path.resolve() != latest_alias.resolve():
        shutil.copyfile(latest_path, latest_alias)

    index_alias = out_dir / "index.html"
    if latest_path.exists() and latest_path.resolve() != index_alias.resolve():
        shutil.copyfile(latest_path, index_alias)

    reports = _discover_reports(out_dir)
    history_path = out_dir / "history.html"
    history_path.write_text(_build_dashboard_html(reports), encoding="utf-8")
    return index_alias
