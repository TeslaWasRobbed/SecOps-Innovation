"""CLI entry point: python -m homepage"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from homepage.generator import generate_homepage

console = Console()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate SecOps Innovation homepage")
    parser.add_argument(
        "--output",
        default="index.html",
        help="Output path for homepage (default: index.html)"
    )
    parser.add_argument(
        "--auto-open",
        action="store_true",
        help="Automatically open the homepage in browser after generation"
    )
    
    args = parser.parse_args(argv)
    
    console.print("\n[bold cyan]SecOps Innovation Homepage[/bold cyan] — generating dynamic homepage...\n")
    
    try:
        output_path = generate_homepage(args.output)
        console.print("[green]SUCCESS[/green] Homepage generated successfully!")
        console.print(f"[dim]Saved to: {output_path}[/dim]")
        
        # Get absolute path for browser
        abs_path = Path(output_path).absolute()
        console.print(f"[dim]Open in browser: file://{abs_path}[/dim]")
        
        if args.auto_open:
            import webbrowser
            webbrowser.open(f"file://{abs_path}")
            console.print("[dim]Opened in default browser[/dim]")
        
        console.print("\n[bold green]SecOps Innovation Platform Ready![/bold green]")
        console.print("[dim]The homepage will automatically update when you generate new content.[/dim]\n")
        
        return 0
        
    except Exception as exc:
        console.print(f"[bold red]Error generating homepage:[/bold red] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())