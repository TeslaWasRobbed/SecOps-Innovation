"""Dual output: Rich terminal rendering + Markdown file writer."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

console = Console()


# Rich terminal helpers

def print_panel(title: str, body: str, *, subtitle: str = "", style: str = "bold cyan") -> None:
    # Fix windows console encoding issue
    import sys
    if sys.platform == "win32":
        body = body.replace("\u2011", "-")
    console.print(Panel(Markdown(body), title=title, subtitle=subtitle, border_style=style, padding=(1, 2)))


def print_table(title: str, columns: list[str], rows: list[list[Any]]) -> None:
    table = Table(title=title, show_lines=True)
    for col in columns:
        table.add_column(col)
    for row in rows:
        table.add_row(*[str(c) for c in row])
    console.print(table)


def print_kql(code: str, title: str = "KQL Rule") -> None:
    from rich.syntax import Syntax

    syntax = Syntax(code, "yaml", theme="monokai", line_numbers=True)
    console.print(Panel(syntax, title=title, border_style="green", padding=(1, 2)))


# Markdown file writer

def save_markdown(
    output_dir: str | Path,
    filename: str,
    title: str,
    body: str,
    *,
    paste_friendly: bool = False,
) -> Path:
    """Write a Markdown file and return the path.

    If *paste_friendly* is True, *body* is written first (e.g. starts with a Cursor-chat
    instruction), with a short footer; no leading H1 so the file can be copied wholesale into chat.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / filename
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if paste_friendly:
        content = (
            f"{body.rstrip()}\n\n---\n\n"
            f"_Threat digest feed export - {title} - {timestamp} - `{filename}`_\n"
        )
    else:
        content = f"# {title}\n\n*Generated: {timestamp}*\n\n{body}"
    path.write_text(content, encoding="utf-8")
    console.print(f"[dim]Saved -> {path}[/dim]")
    return path
