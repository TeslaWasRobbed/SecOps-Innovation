"""Main CLI entry point for SecOps Innovation platform"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

console = Console()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="SecOps Innovation - Threat Intelligence Platform",
        epilog="""
Examples:
  python -m secops digest                  # Generate threat digest
  python -m secops actor "APT29"           # Get actor profile
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Digest command
    digest_parser = subparsers.add_parser('digest', help='Generate threat digest')
    digest_parser.add_argument('--days', type=int, default=7, help='Lookback days')
    digest_parser.add_argument('--pdf', action='store_true', help='Generate PDF')
    
    # Actor command
    actor_parser = subparsers.add_parser('actor', help='Actor intelligence')
    actor_parser.add_argument('name', nargs='?', help='Actor name')
    actor_parser.add_argument('--search', action='store_true', help='Search mode')
    actor_parser.add_argument('--timeline', action='store_true', help='Show timeline')
    actor_parser.add_argument('--recommendations', action='store_true', help='Include recommendations')
    
    args = parser.parse_args(argv)
    
    if not args.command:
        parser.print_help()
        return 0
    
    try:
        if args.command == 'digest':
            return generate_digest(args)
        elif args.command == 'actor':
            return actor_intelligence(args)
        else:
            console.print(f"[red]Unknown command: {args.command}[/red]")
            return 1
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        return 1
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        return 1



def generate_digest(args) -> int:
    """Generate threat digest."""
    import subprocess
    
    cmd = ["python", "-m", "threat_digest", "--days", str(args.days)]
    if args.pdf:
        cmd.append("--pdf")
    
    return subprocess.call(cmd)


def actor_intelligence(args) -> int:
    """Handle actor intelligence commands."""
    import subprocess
    
    if not args.name:
        cmd = ["python", "-m", "actor_watch"]
    else:
        cmd = ["python", "-m", "actor_watch", args.name]
        
        if args.search:
            cmd.append("--search")
        if args.timeline:
            cmd.append("--timeline")
        if args.recommendations:
            cmd.append("--recommendations")
    
    return subprocess.call(cmd)




if __name__ == "__main__":
    sys.exit(main())