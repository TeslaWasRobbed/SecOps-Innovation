"""CLI entry point: python -m actor_watch [actor_name]"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console

from shared.output import print_panel, print_table, save_markdown
from actor_watch.watch import format_actor_markdown, get_actor_profile, list_all_groups

console = Console()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explore MITRE ATT&CK threat actor profiles.")
    parser.add_argument("actor", nargs="?", default=None, help="Actor name or alias (omit to list all)")
    parser.add_argument("--output-dir", default="actor_watch/output", help="Directory for markdown output")
    args = parser.parse_args(argv)

    if args.actor is None:
        console.print("\n[bold cyan]Actor Watch[/bold cyan] — loading ATT&CK groups...\n")
        groups = list_all_groups()
        rows = [
            [g["id"], g["name"], ", ".join(g["aliases"][:3]), str(g["technique_count"])]
            for g in groups
        ]
        print_table(
            f"ATT&CK Threat Groups ({len(groups)})",
            ["ID", "Name", "Aliases", "Techniques"],
            rows,
        )
        console.print(
            "\n[dim]Tip: run [bold]python -m actor_watch \"APT29\"[/bold] for a full profile.[/dim]\n"
        )
        return 0

    console.print(f"\n[bold cyan]Actor Watch[/bold cyan] — looking up [bold]{args.actor}[/bold]...\n")
    profile = get_actor_profile(args.actor)
    if profile is None:
        console.print(f"[bold red]No group found matching \"{args.actor}\".[/bold red]")
        console.print("[dim]Run [bold]python -m actor_watch[/bold] to see all available groups.[/dim]\n")
        return 1

    body = format_actor_markdown(profile)
    print_panel(profile["name"], body, style="bold magenta")

    safe_name = profile["name"].replace(" ", "_").replace("/", "-")
    save_markdown(args.output_dir, f"{safe_name}.md", profile["name"], body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
