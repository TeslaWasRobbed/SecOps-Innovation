"""Generate reviewable Microsoft Sentinel analytic rule YAML drafts."""

from __future__ import annotations

import argparse
import html
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from shared.llm import complete
from threat_digest.profile import load_company_profile, profile_to_prompt_block, resolve_profile_path

console = Console()

DEFAULT_GUIDE = Path("Templates") / "AnalyticRuleGuide"
DEFAULT_DIGEST_DIR = Path("output") / "threat_digest"
DEFAULT_OUTPUT_DIR = Path("output") / "detections" / "drafts"
DEFAULT_INDEX = Path("output") / "detections" / "index.html"
DEFAULT_MAX_TOKENS = 16384


@dataclass(frozen=True)
class DetectionItem:
    """A digest item suitable for rule generation."""

    index: int
    section: str
    title: str
    context: str
    source_path: Path | None = None


def _strip_markdown(value: str) -> str:
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", value)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = text.replace("\u00e2\u20ac\u201d", "-").replace("\u2014", "-")
    text = text.replace("\u2011", "-").replace("\u2010", "-").replace("\u2013", "-")
    text = text.replace("\u2018", "'").replace("\u2019", "'").replace("\u201c", '"').replace("\u201d", '"')
    return re.sub(r"\s+", " ", text).strip()


def _console_safe(value: str) -> str:
    return value


def _slugify(value: str, max_len: int = 72) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    return (slug[:max_len].strip("-") or "sentinel-rule-draft")


def latest_digest_path(digest_dir: Path = DEFAULT_DIGEST_DIR) -> Path | None:
    candidates = sorted(
        digest_dir.glob("digest_*.md"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def extract_digest_items(path: Path) -> list[DetectionItem]:
    """Extract top-level threat bullets from a generated digest Markdown file."""
    text = path.read_text(encoding="utf-8", errors="replace")
    items: list[DetectionItem] = []
    section = ""
    current: list[str] = []

    def flush() -> None:
        if not current:
            return
        block = "\n".join(current).strip()
        first = current[0].strip()
        title_raw = re.sub(r"^-\s+", "", first)
        title_raw = re.sub(r"\s+\(\*\*[^)]+\*\*\)\s*$", "", title_raw)
        title = _strip_markdown(title_raw)
        if title and section.lower() in {
            "key vulnerabilities to act on",
            "notable campaigns & incidents",
            "notable campaigns and incidents",
        }:
            items.append(
                DetectionItem(
                    index=len(items) + 1,
                    section=section,
                    title=title,
                    context=block,
                    source_path=path,
                )
            )

    for raw_line in text.splitlines():
        heading = re.match(r"^##\s+(.+?)\s*$", raw_line)
        if heading:
            flush()
            current = []
            section = _strip_markdown(heading.group(1)).lower()
            continue
        if re.match(r"^-\s+", raw_line):
            flush()
            current = [raw_line]
            continue
        if current:
            current.append(raw_line)
    flush()
    return items


def _load_guide(path: Path) -> str:
    if not path.is_file():
        raise FileNotFoundError(f"Detection guide not found: {path}")
    return path.read_text(encoding="utf-8", errors="replace").strip()


def _profile_block(profile_path: str | None) -> str:
    resolved = resolve_profile_path(profile_path)
    profile = load_company_profile(resolved)
    return profile_to_prompt_block(profile)


def _build_prompt(
    *,
    item: DetectionItem,
    guide: str,
    profile_block: str,
    rule_id: str,
) -> str:
    return f"""Create one Microsoft Sentinel scheduled analytics rule YAML draft.

Use the Sentinel rule guidance exactly. The rule must be practical, reviewable, and default to disabled.
Do not claim the rule is production-ready. Do not include markdown fences or prose outside the YAML.

## Generated rule ID

{rule_id}

## Organisation profile

{profile_block}

## Threat item selected by analyst

Section: {item.section}
Title: {item.title}

Context:
{item.context}

## Additional constraints

- Set `id` to `{rule_id}`.
- Set `enabled: false`.
- Prefer `status: Experimental` when the source item lacks concrete IOCs or confirmed telemetry.
- Use Microsoft Sentinel data sources that fit the organisation profile, especially Microsoft Sentinel, Defender for Endpoint, Entra ID, email, cloud, and network telemetry where relevant.
- If exact IOCs are unavailable, write behavioural KQL that is clearly labelled as a draft hypothesis and avoids brittle fake indicators.
- Keep KQL maintainable and analyst-readable.
- Include a changelog entry for initial release dated {datetime.now(timezone.utc).strftime("%Y-%m-%d")}.

## Sentinel rule guide

{guide}
"""


def _strip_yaml_fence(text: str) -> str:
    out = (text or "").strip()
    match = re.search(r"```(?:yaml|yml)?\s*([\s\S]*?)```", out, flags=re.IGNORECASE)
    if match:
        out = match.group(1).strip()
    return out


def validate_yaml_draft(yaml_text: str) -> tuple[bool, str]:
    try:
        parsed = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        return False, str(exc)
    if not isinstance(parsed, dict):
        return False, "YAML did not parse to a mapping/object."
    required = ["id", "name", "description", "query", "tactics", "version", "kind"]
    missing = [key for key in required if key not in parsed]
    if missing:
        return False, "Missing required field(s): " + ", ".join(missing)
    if parsed.get("enabled") is not False:
        return False, "Generated rule must default to enabled: false."
    return True, "YAML parsed and required draft fields are present."


def list_detection_drafts(root: Path = DEFAULT_OUTPUT_DIR) -> list[dict[str, Any]]:
    """Return generated YAML drafts with parsed display metadata."""
    drafts = sorted(root.glob("*/*.yaml"), key=lambda p: p.stat().st_mtime, reverse=True) if root.exists() else []
    rows: list[dict[str, Any]] = []
    for draft in drafts:
        text = draft.read_text(encoding="utf-8", errors="replace")
        parsed: dict[str, Any] = {}
        valid = True
        validation_message = "YAML parsed."
        try:
            loaded = yaml.safe_load(text)
            parsed = loaded if isinstance(loaded, dict) else {}
            if not parsed:
                valid = False
                validation_message = "YAML did not parse to a mapping/object."
        except yaml.YAMLError as exc:
            valid = False
            validation_message = str(exc)
        rows.append(
            {
                "path": str(draft),
                "date": draft.parent.name,
                "name": str(parsed.get("name") or draft.stem),
                "severity": str(parsed.get("severity") or "-"),
                "status": str(parsed.get("status") or "Needs review"),
                "enabled": parsed.get("enabled"),
                "kind": str(parsed.get("kind") or "-"),
                "valid": valid,
                "validation_message": validation_message,
                "yaml": text,
            }
        )
    return rows


def generate_rule_draft(
    item: DetectionItem,
    *,
    guide_path: Path = DEFAULT_GUIDE,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    profile_path: str | None = None,
    max_tokens: int = DEFAULT_MAX_TOKENS,
) -> tuple[Path, str, str]:
    guide = _load_guide(guide_path)
    rule_id = str(uuid.uuid4())
    prompt = _build_prompt(
        item=item,
        guide=guide,
        profile_block=_profile_block(profile_path),
        rule_id=rule_id,
    )
    raw = complete(
        prompt,
        system=(
            "You are a senior detection engineer producing Microsoft Sentinel analytics "
            "rule YAML for human review. Output YAML only."
        ),
        max_tokens=max_tokens,
    )
    yaml_text = _strip_yaml_fence(raw)
    valid, validation_message = validate_yaml_draft(yaml_text)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    output_dir = output_dir / stamp
    output_dir.mkdir(parents=True, exist_ok=True)
    prefix = "valid" if valid else "needs-review"
    path = output_dir / f"{prefix}_{_slugify(item.title)}.yaml"
    path.write_text(yaml_text + "\n", encoding="utf-8")
    write_detection_index(DEFAULT_INDEX)
    return path, validation_message, yaml_text


def write_detection_index(index_path: Path = DEFAULT_INDEX) -> Path:
    rows: list[str] = []
    for draft in list_detection_drafts(index_path.parent / "drafts"):
        draft_path = Path(str(draft["path"]))
        rel = draft_path.relative_to(index_path.parent).as_posix()
        rows.append(
            "<article class='rule-card'>"
            f"<div><h2>{html.escape(str(draft['name']))}</h2>"
            f"<p>{html.escape(str(draft['status']))} | {html.escape(str(draft['severity']))} | {html.escape(str(draft['date']))}</p></div>"
            f"<a href='{html.escape(rel)}'>Open YAML</a>"
            f"<button type='button' data-copy='{html.escape(rel)}'>Copy</button>"
            f"<pre>{html.escape(str(draft['yaml']))}</pre>"
            "</article>"
        )

    body = "\n".join(rows) if rows else "<p>No detection drafts generated yet.</p>"
    doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Detection Drafts</title>
  <style>
    :root {{ color-scheme: dark; --bg: #07111f; --panel: #101f34; --line: #2a3d5c; --text: #e7f1ff; --muted: #9eb3ce; --accent: #5eead4; }}
    body {{ margin: 0; font-family: Segoe UI, Arial, sans-serif; background: var(--bg); color: var(--text); }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 32px 18px 60px; }}
    header {{ display: flex; justify-content: space-between; gap: 16px; align-items: end; margin-bottom: 22px; }}
    h1 {{ margin: 0; font-size: clamp(28px, 4vw, 48px); }}
    p {{ color: var(--muted); }}
    .nav {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .nav a {{ border: 1px solid var(--line); background: #132844; color: var(--text); border-radius: 6px; padding: 8px 10px; text-decoration: none; }}
    .nav a:hover {{ border-color: var(--accent); }}
    .rule-card {{ min-width: 0; border: 1px solid var(--line); background: var(--panel); border-radius: 8px; padding: 18px; margin: 14px 0; }}
    .rule-card h2 {{ margin: 0 0 6px; font-size: 20px; }}
    .rule-card a, button {{ border: 1px solid var(--line); background: #132844; color: var(--text); border-radius: 6px; padding: 8px 10px; margin-right: 8px; cursor: pointer; text-decoration: none; }}
    .rule-card a:hover, button:hover {{ border-color: var(--accent); }}
    pre {{ width: 100%; max-width: 100%; overflow: auto; max-height: min(520px, 62vh); padding: 14px; background: #07111f; border: 1px solid var(--line); border-radius: 6px; white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; }}
    @media (max-width: 760px) {{ header {{ display: grid; }} }}
  </style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>Detection Drafts</h1>
      <p>Generated Sentinel analytic rule YAML for analyst review. Drafts are disabled by default.</p>
    </div>
    <nav class="nav">
      <a href="/">Workbench</a>
      <a href="../threat_digest/index.html">Latest Digest</a>
      <a href="../actor_watch/index.html">Actor Watch</a>
    </nav>
  </header>
  {body}
</main>
<script>
document.querySelectorAll("[data-copy]").forEach(function(btn) {{
  btn.addEventListener("click", function() {{
    var pre = btn.closest(".rule-card").querySelector("pre");
    navigator.clipboard.writeText(pre.textContent || "");
    btn.textContent = "Copied";
    setTimeout(function() {{ btn.textContent = "Copy"; }}, 1200);
  }});
}});
</script>
</body>
</html>
"""
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(doc, encoding="utf-8")
    return index_path


def _print_items(items: list[DetectionItem]) -> None:
    table = Table(title="Digest Items Available for Detection Drafting", show_lines=True)
    table.add_column("#", justify="right")
    table.add_column("Section")
    table.add_column("Title")
    for item in items:
        table.add_row(str(item.index), item.section.title(), _console_safe(item.title))
    console.print(table)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate Microsoft Sentinel analytic rule YAML drafts.")
    parser.add_argument("--from-digest", default=None, metavar="PATH", help="Generated digest Markdown to use")
    parser.add_argument("--latest", action="store_true", help="Use the latest digest Markdown")
    parser.add_argument("--list", action="store_true", help="List selectable digest items and exit")
    parser.add_argument("--item", type=int, default=None, help="Digest item number to generate from")
    parser.add_argument("--title", default=None, help="Manual threat title when not using a digest item")
    parser.add_argument("--context", default=None, help="Manual threat context when not using a digest item")
    parser.add_argument("--guide", default=str(DEFAULT_GUIDE), help="Path to detection guidance template")
    parser.add_argument("--profile", default=None, metavar="PATH", help="YAML company profile")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Directory for YAML drafts")
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS, help="LLM output token budget")
    parser.add_argument("--index", action="store_true", help="Regenerate detection review page only")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.index:
        path = write_detection_index()
        console.print(f"[green]Updated detection review page:[/green] {path}")
        return 0

    digest_path: Path | None = None
    if args.from_digest:
        digest_path = Path(args.from_digest)
    elif args.latest or not (args.title or args.context):
        digest_path = latest_digest_path()

    items: list[DetectionItem] = []
    if digest_path:
        if not digest_path.is_file():
            console.print(f"[red]Digest file not found:[/red] {digest_path}")
            return 1
        items = extract_digest_items(digest_path)
        if args.list:
            _print_items(items)
            return 0
        if not items and not args.title:
            console.print(f"[yellow]No detection-ready items found in:[/yellow] {digest_path}")
            return 1

    if args.title or args.context:
        title = args.title or "Manual detection request"
        item = DetectionItem(
            index=1,
            section="Manual request",
            title=title,
            context=args.context or title,
            source_path=None,
        )
    else:
        if args.item is None:
            _print_items(items)
            console.print("\nUse [bold]--item <number>[/bold] to generate a draft.")
            return 0
        selected = [item for item in items if item.index == args.item]
        if not selected:
            console.print(f"[red]No digest item #{args.item}[/red]")
            return 1
        item = selected[0]

    console.print(Panel(_console_safe(item.title), title="Generating Detection Draft", border_style="cyan"))
    try:
        path, validation_message, _ = generate_rule_draft(
            item,
            guide_path=Path(args.guide),
            output_dir=Path(args.output_dir),
            profile_path=args.profile,
            max_tokens=args.max_tokens,
        )
    except Exception as exc:
        console.print(f"[red]Detection generation failed:[/red] {exc}")
        return 1

    console.print(f"[green]Saved draft:[/green] {path}")
    console.print(f"[dim]{validation_message}[/dim]")
    console.print(f"[dim]Review page:[/dim] {DEFAULT_INDEX}")
    return 0
