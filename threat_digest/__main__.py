"""CLI entry point: python -m threat_digest"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from rich.console import Console

from shared.output import print_panel, save_markdown
from threat_digest.digest import build_digest

console = Console()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a stakeholder-friendly threat digest.")
    parser.add_argument("--days", type=int, default=7, help="Look-back window in days (default: 7)")
    parser.add_argument("--output-dir", default="threat_digest/output", help="Directory for markdown output")
    args = parser.parse_args(argv)

    console.print("\n[bold cyan]Threat Digest[/bold cyan] — fetching intelligence...\n")

    try:
        result = build_digest(days=args.days)
    except RuntimeError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 1

    stats = f"{result['kev_count']} KEVs | {result['article_count']} articles | last {args.days} days"
    print_panel("Threat Digest", result["summary"], subtitle=stats, style="bold cyan")

    datestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    save_markdown(
        args.output_dir,
        f"digest_{datestamp}.md",
        f"Threat Digest — {datestamp}",
        result["summary"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
