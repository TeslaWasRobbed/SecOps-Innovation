"""Main CLI entry point for SecOps Innovation platform"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

console = Console()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="SecOps Innovation - Advanced Threat Intelligence Platform",
        epilog="""
Examples:
  python -m secops init                    # Initialize platform and generate homepage
  python -m secops digest                  # Generate threat digest
  python -m secops actor "APT29"           # Get actor profile
  python -m secops dashboard               # Open monitoring dashboard
  python -m secops serve                   # Start local web server
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Init command
    init_parser = subparsers.add_parser('init', help='Initialize the platform')
    init_parser.add_argument('--open', action='store_true', help='Open homepage in browser')
    
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
    
    # Dashboard command
    dashboard_parser = subparsers.add_parser('dashboard', help='Generate monitoring dashboard')
    dashboard_parser.add_argument('--open', action='store_true', help='Open in browser')
    
    # Serve command
    serve_parser = subparsers.add_parser('serve', help='Start local web server')
    serve_parser.add_argument('--port', type=int, default=8000, help='Port number')
    
    args = parser.parse_args(argv)
    
    if not args.command:
        parser.print_help()
        return 0
    
    try:
        if args.command == 'init':
            return init_platform(args)
        elif args.command == 'digest':
            return generate_digest(args)
        elif args.command == 'actor':
            return actor_intelligence(args)
        elif args.command == 'dashboard':
            return generate_dashboard(args)
        elif args.command == 'serve':
            return serve_platform(args)
        else:
            console.print(f"[red]Unknown command: {args.command}[/red]")
            return 1
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        return 1
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        return 1


def init_platform(args) -> int:
    """Initialize the SecOps Innovation platform."""
    console.print("\n[bold cyan]SecOps Innovation Platform[/bold cyan]")
    console.print("[dim]Initializing advanced threat intelligence platform...[/dim]\n")
    
    # Generate homepage
    from homepage.generator import generate_homepage
    
    homepage_path = generate_homepage("index.html")
    console.print("[green]SUCCESS[/green] Homepage generated")
    
    # Create output directories
    Path("output/threat_digest").mkdir(parents=True, exist_ok=True)
    Path("output/actor_watch").mkdir(parents=True, exist_ok=True)
    console.print("[green]SUCCESS[/green] Directory structure created")
    
    # Generate initial dashboard
    from actor_watch.dashboard import generate_actor_dashboard
    dashboard_path = generate_actor_dashboard("output/actor_watch/dashboard.html")
    console.print("[green]SUCCESS[/green] Monitoring dashboard created")
    
    console.print(f"\n[bold green]Platform Ready![/bold green]")
    console.print(f"[dim]Homepage: file://{Path(homepage_path).absolute()}[/dim]")
    console.print(f"[dim]Dashboard: file://{Path(dashboard_path).absolute()}[/dim]")
    
    if args.open:
        import webbrowser
        webbrowser.open(f"file://{Path(homepage_path).absolute()}")
        console.print("[dim]Opened homepage in browser[/dim]")
    
    console.print("\n[bold]Next steps:[/bold]")
    console.print("• [cyan]python -m secops digest[/cyan] - Generate threat digest")
    console.print("• [cyan]python -m secops actor \"APT29\"[/cyan] - Get actor profile")
    console.print("• [cyan]python -m secops serve[/cyan] - Start web server")
    
    return 0


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


def generate_dashboard(args) -> int:
    """Generate monitoring dashboard."""
    import subprocess
    
    cmd = ["python", "-m", "actor_watch", "--dashboard"]
    result = subprocess.call(cmd)
    
    if result == 0 and args.open:
        import webbrowser
        dashboard_path = Path("output/actor_watch/dashboard.html").absolute()
        webbrowser.open(f"file://{dashboard_path}")
        console.print("[dim]Opened dashboard in browser[/dim]")
    
    return result


def serve_platform(args) -> int:
    """Start local web server."""
    import http.server
    import socketserver
    import webbrowser
    from pathlib import Path
    
    # Check if homepage exists
    if not Path("index.html").exists():
        console.print("[yellow]Homepage not found. Initializing platform...[/yellow]")
        init_result = init_platform(type('Args', (), {'open': False})())
        if init_result != 0:
            return init_result
    
    port = args.port
    handler = http.server.SimpleHTTPRequestHandler
    
    try:
        with socketserver.TCPServer(("", port), handler) as httpd:
            console.print(f"\n[bold green]SecOps Innovation Platform Server[/bold green]")
            console.print(f"[dim]Serving at http://localhost:{port}[/dim]")
            console.print(f"[dim]Press Ctrl+C to stop[/dim]\n")
            
            # Open browser
            webbrowser.open(f"http://localhost:{port}")
            
            httpd.serve_forever()
            
    except OSError as e:
        if e.errno == 48:  # Address already in use
            console.print(f"[red]Port {port} is already in use. Try a different port with --port[/red]")
            return 1
        raise
    
    return 0


if __name__ == "__main__":
    sys.exit(main())