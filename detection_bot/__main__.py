"""CLI entry point: python -m detection_bot T1078"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from shared.output import print_kql, save_markdown
from detection_bot.bot import generate_rule

console = Console()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a Sentinel KQL detection rule for an ATT&CK technique.")
    parser.add_argument("technique", help="ATT&CK technique ID, e.g. T1078 or T1003.006")
    parser.add_argument("--severity", default=None, help="Suggest a severity (High, Medium, Low)")
    parser.add_argument("--data-sources", nargs="*", default=None, help="Override data sources")
    parser.add_argument("--output-dir", default="output/detection_bot", help="Directory for output files")
    args = parser.parse_args(argv)

    tid = args.technique.upper()
    console.print(f"\n[bold cyan]Detection Bot[/bold cyan] — generating rule for [bold]{tid}[/bold]...\n")

    try:
        result = generate_rule(tid, severity=args.severity, data_sources=args.data_sources)
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 1
    except RuntimeError as exc:
        console.print(f"[bold red]API Error:[/bold red] {exc}")
        return 1

    print_kql(result["rule_text"], title=f"{tid} — {result['technique_name']}")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    kql_path = out_dir / f"{tid}.kql"
    kql_path.write_text(result["rule_text"], encoding="utf-8")
    console.print(f"[dim]Saved rule → {kql_path}[/dim]")

    save_markdown(
        out_dir,
        f"{tid}.md",
        f"Detection Rule: {tid} — {result['technique_name']}",
        f"**Tactics:** {', '.join(result['tactics'])}\n\n```yaml\n{result['rule_text']}\n```",
    )

    console.print(
        f"\n[green]Done.[/green] Rule for {tid} saved to [bold]{kql_path}[/bold]. "
        "Copy it to your sample_rules/ folder to include it in coverage analysis.\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
