"""Platform CLI entry point: python -m secops."""

from __future__ import annotations

import argparse
import sys
import webbrowser
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

console = Console()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SecOps Innovation - Threat Intelligence Platform",
        epilog="""\
Examples:
  python -m secops digest --days 7
  python -m secops digest --no-llm --no-html
  python -m secops detection --latest --list
  python -m secops detection --latest --item 1
  python -m secops web
  python -m secops ui
  python -m secops tracking --refresh
  python -m secops actor "APT29" --recommendations
  python -m secops actor --dashboard
  python -m secops header --file suspicious_email.txt
  python -m secops osint 8.8.8.8
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    digest_parser = subparsers.add_parser("digest", help="Generate threat digest")
    digest_parser.add_argument("--days", type=int, default=7, help="Look-back window in days")
    digest_parser.add_argument("--output-dir", default="output/threat_digest", help="Directory for digest output")
    digest_parser.add_argument("--profile", default=None, metavar="PATH", help="YAML company profile")
    digest_parser.add_argument("--no-llm", action="store_true", help="Skip AI summary")
    digest_parser.add_argument("--no-claude", action="store_true", help="Alias for --no-llm")
    digest_parser.add_argument("--no-html", action="store_true", help="Skip HTML output")
    digest_parser.add_argument("--pdf", action="store_true", help="Generate PDF output")

    actor_parser = subparsers.add_parser("actor", help="Actor intelligence")
    actor_parser.add_argument("actor", nargs="?", default=None, help="Actor name or alias")
    actor_parser.add_argument("--output-dir", default="output/actor_watch", help="Directory for actor output")
    actor_parser.add_argument("--search", action="store_true", help="Search mode")
    actor_parser.add_argument("--timeline", action="store_true", help="Show activity timeline")
    actor_parser.add_argument("--recommendations", action="store_true", help="Include defensive recommendations")
    actor_parser.add_argument("--source", choices=["all", "mitre", "microsoft"], default="all")
    actor_parser.add_argument("--days", type=int, default=30, help="Look-back days for activity")
    actor_parser.add_argument("--dashboard", action="store_true", help="Generate actor dashboard")

    tracking_parser = subparsers.add_parser("tracking", help="Show actor mention tracking")
    tracking_parser.add_argument(
        "--refresh",
        action="store_true",
        help="Rescan digest reports before showing tracking stats",
    )

    detection_parser = subparsers.add_parser("detection", help="Generate Sentinel detection YAML drafts")
    detection_parser.add_argument("--from-digest", default=None, metavar="PATH", help="Generated digest Markdown to use")
    detection_parser.add_argument("--latest", action="store_true", help="Use the latest digest Markdown")
    detection_parser.add_argument("--list", action="store_true", help="List selectable digest items and exit")
    detection_parser.add_argument("--item", type=int, default=None, help="Digest item number to generate from")
    detection_parser.add_argument("--title", default=None, help="Manual threat title")
    detection_parser.add_argument("--context", default=None, help="Manual threat context")
    detection_parser.add_argument("--guide", default="Templates/AnalyticRuleGuide", help="Path to detection guidance")
    detection_parser.add_argument("--profile", default=None, metavar="PATH", help="YAML company profile")
    detection_parser.add_argument("--output-dir", default="output/detections/drafts", help="Directory for YAML drafts")
    detection_parser.add_argument("--max-tokens", type=int, default=16384, help="LLM output token budget")
    detection_parser.add_argument("--index", action="store_true", help="Regenerate detection review page only")

    web_parser = subparsers.add_parser("web", help="Run the local browser workbench")
    web_parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    web_parser.add_argument("--port", type=int, default=8765, help="Bind port")
    web_parser.add_argument("--no-open", action="store_true", help="Do not open a browser")

    header_parser = subparsers.add_parser("header", help="Analyze raw email/message headers")
    header_parser.add_argument("--file", default=None, metavar="PATH", help="File with raw headers or a full .eml (default: read from stdin)")
    header_parser.add_argument("--known-domains", default=None, help="Comma-separated organisation domains (default: known_domains from company_profile.yaml)")

    osint_parser = subparsers.add_parser("osint", help="OSINT lookup for a domain, IP, or file hash")
    osint_parser.add_argument("query", help="Domain, IP address, or file hash (md5/sha1/sha256)")

    subparsers.add_parser("ui", help="Open the guided command-line menu")

    return parser


def _run_digest(args: argparse.Namespace) -> int:
    from threat_digest.__main__ import main as digest_main

    forwarded = ["--days", str(args.days), "--output-dir", args.output_dir]
    if args.profile:
        forwarded.extend(["--profile", args.profile])
    if args.no_llm or args.no_claude:
        forwarded.append("--no-llm")
    if args.no_html:
        forwarded.append("--no-html")
    if args.pdf:
        forwarded.append("--pdf")
    return digest_main(forwarded)


def _run_actor(args: argparse.Namespace) -> int:
    from actor_watch.__main__ import main as actor_main

    forwarded: list[str] = []
    if args.actor:
        forwarded.append(args.actor)
    forwarded.extend(["--output-dir", args.output_dir])
    if args.search:
        forwarded.append("--search")
    if args.timeline:
        forwarded.append("--timeline")
    if args.recommendations:
        forwarded.append("--recommendations")
    forwarded.extend(["--source", args.source, "--days", str(args.days)])
    if args.dashboard:
        forwarded.append("--dashboard")
    return actor_main(forwarded)


def _run_tracking(refresh: bool = False) -> int:
    from shared.actor_tracking import load_tracking_data, update_actor_tracking

    tracking_data = update_actor_tracking() if refresh else load_tracking_data()
    actors = tracking_data.get("actors", {})
    rows = [
        actor
        for actor in actors.values()
        if int(actor.get("total_mentions", 0) or 0) > 0
    ]
    rows.sort(key=lambda actor: int(actor.get("total_mentions", 0) or 0), reverse=True)

    console.print(
        Panel(
            f"Digests scanned: {tracking_data.get('total_digests_scanned', 0)}\n"
            f"Last updated: {tracking_data.get('last_updated') or 'never'}",
            title="Actor Tracking",
            border_style="cyan",
        )
    )

    if not rows:
        console.print("[yellow]No tracked actor mentions found yet.[/yellow]")
        return 0

    table = Table(title="Tracked Actor Mentions", show_lines=True)
    table.add_column("Actor")
    table.add_column("Type")
    table.add_column("Mentions", justify="right")
    table.add_column("Reports", justify="right")
    table.add_column("Last Seen")
    for actor in rows:
        table.add_row(
            str(actor.get("name", "")),
            str(actor.get("type", "")).replace("_", " ").title(),
            str(actor.get("total_mentions", 0)),
            str(actor.get("digest_appearances", 0)),
            str(actor.get("last_seen") or "-"),
        )
    console.print(table)
    return 0


def _run_detection(args: argparse.Namespace) -> int:
    from detection.generator import main as detection_main

    forwarded: list[str] = []
    if args.from_digest:
        forwarded.extend(["--from-digest", args.from_digest])
    if args.latest:
        forwarded.append("--latest")
    if args.list:
        forwarded.append("--list")
    if args.item is not None:
        forwarded.extend(["--item", str(args.item)])
    if args.title:
        forwarded.extend(["--title", args.title])
    if args.context:
        forwarded.extend(["--context", args.context])
    if args.guide:
        forwarded.extend(["--guide", args.guide])
    if args.profile:
        forwarded.extend(["--profile", args.profile])
    if args.output_dir:
        forwarded.extend(["--output-dir", args.output_dir])
    if args.max_tokens:
        forwarded.extend(["--max-tokens", str(args.max_tokens)])
    if args.index:
        forwarded.append("--index")
    return detection_main(forwarded)


def _run_web(args: argparse.Namespace) -> int:
    from detection.web import main as web_main

    forwarded = ["--host", args.host, "--port", str(args.port)]
    if args.no_open:
        forwarded.append("--no-open")
    return web_main(forwarded)


def _run_header(args: argparse.Namespace) -> int:
    from analysis.email_header import analyze_message
    from threat_digest.profile import load_known_domains

    if args.file:
        raw = Path(args.file).read_text(encoding="utf-8", errors="replace")
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    else:
        console.print("[yellow]Paste raw headers or a full .eml, then press Ctrl+D (Ctrl+Z on Windows, Enter) to finish:[/yellow]")
        raw = sys.stdin.read()

    if not raw.strip():
        console.print("[red]No header/message text provided.[/red]")
        return 1

    known_domains = (
        [d.strip() for d in args.known_domains.split(",") if d.strip()]
        if args.known_domains
        else load_known_domains()
    )
    result = analyze_message(raw, known_domains=known_domains)

    risk = result["risk"]
    risk_style = {"High": "red", "Medium": "yellow", "Low": "cyan", "Informational": "green"}.get(risk["level"], "white")
    console.print(
        Panel(
            f"[bold {risk_style}]{risk['level']} risk[/bold {risk_style}] (heuristic score {risk['score']})",
            title="Header Analysis",
            border_style=risk_style,
        )
    )

    auth = result["authentication"]
    console.print(f"SPF: [bold]{auth['spf']}[/bold]  DKIM: [bold]{auth['dkim']}[/bold]  DMARC: [bold]{auth['dmarc']}[/bold]")

    h = result["headers"]
    from_disp = f"{h['from']['name']} <{h['from']['address']}>" if h.get("from") else "-"
    console.print(f"From: {from_disp}")
    console.print(f"Reply-To: {h['reply_to']['address'] if h.get('reply_to') else '-'}")
    console.print(f"Subject: {h.get('subject') or '-'}")

    if result["spoofing_signals"]:
        table = Table(title="Spoofing Signals", show_lines=True)
        table.add_column("Severity")
        table.add_column("Detail")
        for sig in result["spoofing_signals"]:
            table.add_row(sig["severity"], sig["detail"])
        console.print(table)

    if result["hops"]:
        table = Table(title="Hop Timeline", show_lines=True)
        table.add_column("#", justify="right")
        table.add_column("From")
        table.add_column("By")
        table.add_column("Date")
        table.add_column("Flags")
        for hop in result["hops"]:
            table.add_row(
                str(hop["index"]),
                str(hop.get("from") or "-"),
                str(hop.get("by") or "-"),
                str(hop.get("date") or "-"),
                "; ".join(hop.get("flags") or []) or "-",
            )
        console.print(table)

    iocs = result["iocs"]
    ioc_list = list(iocs.get("domains") or []) + [i["value"] for i in iocs.get("ips") or []]
    if ioc_list:
        console.print(f"[bold]Extracted IOCs:[/bold] {', '.join(ioc_list)}")

    for warning in result["warnings"]:
        console.print(f"[yellow]Note:[/yellow] {warning}")

    return 0


def _run_osint(query: str) -> int:
    from analysis.osint import run_osint_lookup

    result = run_osint_lookup(query)
    if result.get("error"):
        console.print(f"[red]{result['error']}[/red]")
        return 1

    console.print(Panel(f"[bold]{result['query']}[/bold] ({result['type']})", title="OSINT Lookup", border_style="cyan"))

    rdap = result.get("rdap") or {}
    if rdap.get("available"):
        table = Table(title="RDAP", show_lines=True)
        table.add_column("Field")
        table.add_column("Value")
        for key, value in rdap.items():
            if key in ("available", "events"):
                continue
            display = ", ".join(value) if isinstance(value, list) else str(value or "-")
            table.add_row(key.replace("_", " ").title(), display)
        console.print(table)
    else:
        console.print(f"[yellow]RDAP:[/yellow] {rdap.get('error', 'Not available.')}")

    vt = result.get("virustotal") or {}
    if vt.get("available"):
        vt_style = "red" if vt.get("malicious", 0) > 0 else "green"
        console.print(
            f"[bold]VirusTotal:[/bold] [{vt_style}]malicious={vt.get('malicious', 0)}[/{vt_style}] "
            f"suspicious={vt.get('suspicious', 0)} harmless={vt.get('harmless', 0)} — {vt.get('link', '')}"
        )
    else:
        console.print(f"[yellow]VirusTotal:[/yellow] {vt.get('error', 'Not available.')}")

    return 0


def _open_file(path: Path) -> None:
    if path.exists():
        webbrowser.open(path.resolve().as_uri())
        console.print(f"[green]Opened:[/green] {path}")
    else:
        console.print(f"[yellow]File not found:[/yellow] {path}")


def _console_safe(value: str) -> str:
    return value


def _prompt_days(default: int = 7) -> int:
    return IntPrompt.ask("Look-back days", default=default)


def _run_ui() -> int:
    console.print(
        Panel(
            "Use the number keys to generate reports, open dashboards, or look up actor intelligence.",
            title="SecOps Innovation",
            border_style="cyan",
        )
    )

    while True:
        console.print("\n[bold]Choose an action[/bold]")
        console.print("1. Generate threat digest with AI")
        console.print("2. Generate feed-only threat digest")
        console.print("3. Open threat digest dashboard")
        console.print("4. Search threat actors")
        console.print("5. Generate actor profile")
        console.print("6. Refresh and show actor tracking")
        console.print("7. Generate Sentinel detection draft")
        console.print("8. Open detection draft review")
        console.print("9. Start browser workbench")
        console.print("10. Analyze email/message headers")
        console.print("11. OSINT lookup (domain / IP / hash)")
        console.print("12. Exit")
        choice = Prompt.ask(
            "Selection",
            choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"],
            default="1",
        )

        if choice == "1":
            args = argparse.Namespace(
                days=_prompt_days(7),
                output_dir="output/threat_digest",
                profile=None,
                no_llm=False,
                no_claude=False,
                no_html=False,
                pdf=Confirm.ask("Also generate PDF?", default=False),
            )
            _run_digest(args)
        elif choice == "2":
            args = argparse.Namespace(
                days=_prompt_days(7),
                output_dir="output/threat_digest",
                profile=None,
                no_llm=True,
                no_claude=False,
                no_html=False,
                pdf=False,
            )
            _run_digest(args)
        elif choice == "3":
            _open_file(Path("output/threat_digest/index.html"))
        elif choice == "4":
            query = Prompt.ask("Actor search text")
            args = argparse.Namespace(
                actor=query,
                output_dir="output/actor_watch",
                search=True,
                timeline=False,
                recommendations=False,
                source="all",
                days=30,
                dashboard=False,
            )
            _run_actor(args)
        elif choice == "5":
            actor = Prompt.ask("Actor name")
            args = argparse.Namespace(
                actor=actor,
                output_dir="output/actor_watch",
                search=False,
                timeline=False,
                recommendations=Confirm.ask("Include defensive recommendations?", default=True),
                source="all",
                days=30,
                dashboard=False,
            )
            _run_actor(args)
        elif choice == "6":
            _run_tracking(refresh=True)
        elif choice == "7":
            from detection.generator import extract_digest_items, latest_digest_path

            digest_path = latest_digest_path()
            if not digest_path:
                console.print("[yellow]No digest Markdown found yet. Generate a digest first.[/yellow]")
                continue
            items = extract_digest_items(digest_path)
            if not items:
                console.print(f"[yellow]No detection-ready items found in {digest_path}[/yellow]")
                continue
            table = Table(title="Choose a Digest Item", show_lines=True)
            table.add_column("#", justify="right")
            table.add_column("Section")
            table.add_column("Title")
            for item in items:
                table.add_row(str(item.index), item.section.title(), _console_safe(item.title))
            console.print(table)
            selected = IntPrompt.ask("Item number", default=1)
            args = argparse.Namespace(
                from_digest=str(digest_path),
                latest=False,
                list=False,
                item=selected,
                title=None,
                context=None,
                guide="Templates/AnalyticRuleGuide",
                profile=None,
                output_dir="output/detections/drafts",
                max_tokens=16384,
                index=False,
            )
            _run_detection(args)
        elif choice == "8":
            _open_file(Path("output/detections/index.html"))
        elif choice == "9":
            args = argparse.Namespace(host="127.0.0.1", port=8765, no_open=False)
            _run_web(args)
        elif choice == "10":
            file_path = Prompt.ask("Path to a file with raw headers/.eml (blank to paste directly)", default="")
            args = argparse.Namespace(file=file_path or None, known_domains=None)
            _run_header(args)
        elif choice == "11":
            query = Prompt.ask("Domain, IP address, or file hash")
            _run_osint(query)
        elif choice == "12":
            return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        if sys.stdin.isatty():
            return _run_ui()
        parser.print_help()
        return 0

    try:
        if args.command == "digest":
            return _run_digest(args)
        if args.command == "actor":
            return _run_actor(args)
        if args.command == "tracking":
            return _run_tracking(refresh=args.refresh)
        if args.command == "detection":
            return _run_detection(args)
        if args.command == "web":
            return _run_web(args)
        if args.command == "header":
            return _run_header(args)
        if args.command == "osint":
            return _run_osint(args.query)
        if args.command == "ui":
            return _run_ui()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        return 1

    console.print(f"[red]Unknown command: {args.command}[/red]")
    return 1


if __name__ == "__main__":
    sys.exit(main())
