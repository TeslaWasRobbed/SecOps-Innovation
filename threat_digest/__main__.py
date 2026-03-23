"""CLI entry point: python -m threat_digest"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

import anthropic
from rich.console import Console

from shared.output import print_panel, save_markdown
from threat_digest.digest import build_digest

console = Console()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a stakeholder-friendly threat digest.")
    parser.add_argument("--days", type=int, default=7, help="Look-back window in days (default: 7)")
    parser.add_argument("--output-dir", default="threat_digest/output", help="Directory for markdown output")
    parser.add_argument(
        "--no-claude",
        action="store_true",
        help="Skip Claude: save CISA KEV + RSS only (no Anthropic API; no credits required)",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args(argv)
    skip_claude = args.no_claude or args.no_llm

    console.print("\n[bold cyan]Threat Digest[/bold cyan] — fetching intelligence...\n")

    try:
        result = build_digest(days=args.days, use_llm=not skip_claude)
    except RuntimeError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 1
    except anthropic.BadRequestError as exc:
        body = str(exc)
        console.print(f"[bold red]Anthropic API rejected the request.[/bold red]\n")
        if "credit" in body.lower():
            console.print(
                "Your Anthropic account has [bold]no API credits[/bold] (or billing is not set up).\n"
                "Add credits at: https://console.anthropic.com/settings/plans\n"
            )
        else:
            console.print(f"{body}\n")
        console.print(
            "You can still generate a feed-only digest (no Anthropic API call):\n"
            "  [bold]python -m threat_digest --no-claude[/bold]\n"
        )
        return 1
    except anthropic.APIConnectionError as exc:
        console.print(f"[bold red]Cannot reach Anthropic API:[/bold red] {exc}\n")
        console.print("Try [bold]python -m threat_digest --no-claude[/bold] for a feed-only digest.\n")
        return 1

    mode = "Claude summary" if result.get("used_llm") == "true" else "raw feeds only"
    stats = f"{result['kev_count']} KEVs | {result['article_count']} articles | last {args.days} days | {mode}"
    print_panel("Threat Digest", result["summary"], subtitle=stats, style="bold cyan")

    datestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    save_markdown(
        args.output_dir,
        f"digest_{datestamp}.md",
        f"Threat Digest — {datestamp}",
        result["summary"],
        paste_friendly=skip_claude,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
