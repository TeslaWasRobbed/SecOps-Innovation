"""CLI entry point: python -m actor_watch [actor_name]"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from shared.output import print_panel, print_table, save_markdown
from actor_watch.watch import format_actor_markdown, get_actor_profile, list_all_groups
from actor_watch.enhanced_watch import (
    get_enhanced_actor_profile,
    format_enhanced_actor_markdown,
    list_all_enhanced_actors,
    search_all_actors,
    get_actor_recommendations,
    generate_actor_watch_report
)
from actor_watch.activity_tracker import (
    get_actor_timeline,
    format_activity_timeline_markdown,
    search_actor_mentions
)
from actor_watch.dashboard import generate_actor_dashboard

console = Console()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Enhanced threat actor intelligence from multiple sources.")
    parser.add_argument("actor", nargs="?", default=None, help="Actor name or alias (omit to list all)")
    parser.add_argument(
        "--output-dir",
        default="output/actor_watch",
        help="Directory for markdown output (default: output/actor_watch)",
    )
    parser.add_argument(
        "--search",
        action="store_true",
        help="Search across all sources instead of exact match"
    )
    parser.add_argument(
        "--recommendations",
        action="store_true", 
        help="Include defensive recommendations"
    )
    parser.add_argument(
        "--source",
        choices=["all", "mitre", "microsoft"],
        default="all",
        help="Limit search to specific intelligence source"
    )
    parser.add_argument(
        "--timeline",
        action="store_true",
        help="Show recent activity timeline from security feeds"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Number of days to look back for activity (default: 30)"
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Generate HTML dashboard for threat actor monitoring"
    )
    args = parser.parse_args(argv)

    # Handle dashboard generation first (no actor needed)
    if args.dashboard:
        console.print(f"\n[bold cyan]Threat Actor Dashboard[/bold cyan] — generating HTML dashboard...\n")
        
        from pathlib import Path
        dashboard_path = Path(args.output_dir) / "dashboard.html"
        
        try:
            generated_path = generate_actor_dashboard(dashboard_path, args.days)
            console.print(f"[green]✓[/green] Dashboard generated successfully!")
            console.print(f"[dim]Saved to: {generated_path}[/dim]")
            console.print(f"[dim]Open in browser: file://{Path(generated_path).absolute()}[/dim]\n")
            return 0
        except Exception as exc:
            console.print(f"[bold red]Error generating dashboard:[/bold red] {exc}")
            return 1

    if args.actor is None:
        console.print("\n[bold cyan]Enhanced Actor Watch[/bold cyan] — loading threat intelligence...\n")
        
        if args.source == "mitre":
            groups = list_all_groups()
            rows = [
                [g["id"], g["name"], ", ".join(g["aliases"][:3]), str(g["technique_count"]), "MITRE ATT&CK"]
                for g in groups
            ]
            title = f"MITRE ATT&CK Threat Groups ({len(groups)})"
        elif args.source == "microsoft":
            from shared.microsoft_intel import list_microsoft_actors
            actors = list_microsoft_actors()
            rows = [
                [a["id"], a["name"], ", ".join(a["aliases"][:2]), a.get("type", "").replace("_", " ").title(), "Microsoft"]
                for a in actors
            ]
            title = f"Microsoft Threat Actors ({len(actors)})"
        else:
            # Show all sources
            all_actors = list_all_enhanced_actors()
            rows = []
            for actor in all_actors:
                source_display = "MITRE ATT&CK" if actor["source"] == "mitre_attack" else "Microsoft"
                if actor["source"] == "mitre_attack":
                    rows.append([
                        actor.get("id", ""), 
                        actor["name"], 
                        ", ".join(actor.get("aliases", [])[:2]),
                        str(actor.get("technique_count", 0)),
                        source_display
                    ])
                else:
                    rows.append([
                        actor.get("id", ""),
                        actor["name"],
                        ", ".join(actor.get("aliases", [])[:2]),
                        actor.get("type", "").replace("_", " ").title(),
                        source_display
                    ])
            title = f"All Threat Actors ({len(all_actors)})"
        
        print_table(
            title,
            ["ID", "Name", "Aliases", "Type/Techniques", "Source"],
            rows,
        )
        console.print(
            "\n[dim]Examples:[/dim]"
        )
        console.print("[dim]  • [bold]python -m actor_watch \"Storm-1175\"[/bold] - Microsoft threat actor[/dim]")
        console.print("[dim]  • [bold]python -m actor_watch \"APT29\"[/bold] - MITRE ATT&CK group[/dim]")
        console.print("[dim]  • [bold]python -m actor_watch \"Volt Typhoon\" --recommendations[/bold] - with defenses[/dim]")
        console.print("[dim]  • [bold]python -m actor_watch \"Storm-1175\" --timeline[/bold] - recent activity[/dim]")
        console.print("[dim]  • [bold]python -m actor_watch --dashboard[/bold] - HTML monitoring dashboard[/dim]\n")
        return 0

    # Handle search mode
    if args.search:
        console.print(f"\n[bold cyan]Actor Search[/bold cyan] — searching for [bold]{args.actor}[/bold]...\n")
        results = search_all_actors(args.actor)
        if not results:
            console.print(f"[bold red]No actors found matching \"{args.actor}\".[/bold red]")
            console.print("[dim]Try a different search term or run without arguments to see all actors.[/dim]\n")
            return 1
        
        rows = []
        for result in results:
            source_display = "MITRE ATT&CK" if result["source"] == "mitre_attack" else "Microsoft"
            rows.append([
                result.get("id", ""),
                result["name"],
                ", ".join(result.get("aliases", [])[:2]),
                source_display
            ])
        
        print_table(
            f"Search Results for \"{args.actor}\" ({len(results)})",
            ["ID", "Name", "Aliases", "Source"],
            rows
        )
        console.print(f"\n[dim]Use [bold]python -m actor_watch \"<exact_name>\"[/bold] for full profile.[/dim]\n")
        return 0

    # Handle timeline mode
    if args.timeline:
        console.print(f"\n[bold cyan]Actor Activity Timeline[/bold cyan] — tracking [bold]{args.actor}[/bold]...\n")
        
        timeline_data = get_actor_timeline(args.actor, args.days)
        if not timeline_data.get("timeline"):
            console.print(f"[yellow]{timeline_data['summary']}[/yellow]")
            console.print("[dim]Try increasing --days or check if the actor name is correct.[/dim]\n")
            return 0
        
        # Display summary
        stats = timeline_data.get("stats", {})
        console.print(f"[bold]Activity Summary:[/bold] {timeline_data['summary']}")
        
        if stats:
            console.print(f"[dim]Total mentions: {stats['total_mentions']}, Recent activity: {stats['recent_activity']}[/dim]\n")
        
        # Show recent mentions
        timeline = timeline_data["timeline"]
        console.print("[bold]Recent Mentions:[/bold]")
        
        shown_mentions = 0
        for entry in timeline[:5]:  # Show last 5 days
            date = entry["date"]
            mentions = entry["mentions"]
            
            console.print(f"\n[bold cyan]{date}[/bold cyan] ({len(mentions)} mentions)")
            for mention in mentions[:3]:  # Top 3 per day
                title = mention.get("title", "No title")[:80] + "..." if len(mention.get("title", "")) > 80 else mention.get("title", "No title")
                source = mention.get("source", "Unknown")
                relevance = mention.get("relevance_score", 0)
                console.print(f"  • {title} - [dim]{source} (score: {relevance:.1f})[/dim]")
                shown_mentions += 1
                if shown_mentions >= 10:  # Limit total shown
                    break
            if shown_mentions >= 10:
                break
        
        # Save timeline to file
        timeline_markdown = format_activity_timeline_markdown(timeline_data)
        safe_name = args.actor.replace(" ", "_").replace("/", "-").replace("-", "_")
        filename = f"{safe_name}_timeline.md"
        save_markdown(args.output_dir, filename, f"{args.actor} Activity Timeline", timeline_markdown)
        console.print(f"\n[dim]Full timeline saved to {args.output_dir}/{filename}[/dim]\n")
        
        return 0

    # Handle specific actor lookup
    console.print(f"\n[bold cyan]Enhanced Actor Watch[/bold cyan] — looking up [bold]{args.actor}[/bold]...\n")
    
    # Generate comprehensive report
    report = generate_actor_watch_report(args.actor)
    if "error" in report:
        console.print(f"[bold red]{report['error']}[/bold red]")
        console.print("[dim]Try [bold]--search[/bold] to find similar names, or run without arguments to see all actors.[/dim]\n")
        return 1

    profile = report["profile"]
    body = report["markdown"]
    
    # Add recommendations if requested
    if args.recommendations:
        recommendations = report["recommendations"]
        if recommendations:
            body += "\n\n## Defensive Recommendations\n\n"
            for i, rec in enumerate(recommendations, 1):
                body += f"{i}. {rec}\n"

    # Display the profile
    source_display = "Microsoft Threat Intelligence" if profile["source"] == "microsoft" else "MITRE ATT&CK"
    print_panel(f"{profile['name']} ({source_display})", body, style="bold magenta")

    # Save to file
    safe_name = profile["name"].replace(" ", "_").replace("/", "-").replace("-", "_")
    filename = f"{safe_name}.md"
    save_markdown(args.output_dir, filename, profile["name"], body)
    console.print(f"[dim]Saved to {args.output_dir}/{filename}[/dim]")
    
    # Generate HTML version
    try:
        from actor_watch.html_profile import generate_actor_html_profile
        from pathlib import Path
        
        html_filename = filename.replace('.md', '.html')
        html_path = Path(args.output_dir) / html_filename
        
        generate_actor_html_profile(
            actor_data=profile,
            markdown_content=body,
            output_path=html_path,
            include_timeline=False  # Can be enhanced later
        )
        console.print(f"[dim]Saved HTML to {args.output_dir}/{html_filename}[/dim]")
        
    except ImportError as exc:
        console.print(f"[yellow]Warning: HTML profile generation not available: {exc}[/yellow]")
    except Exception as exc:
        import traceback
        console.print(f"[yellow]Warning: Could not generate HTML profile: {exc}[/yellow]")
        console.print(f"[dim]Debug: {traceback.format_exc()}[/dim]")
    
    console.print()
    
    # Auto-update homepage
    try:
        from shared.auto_update import update_homepage_after_generation
        update_homepage_after_generation("actor_profile", filename)
    except ImportError:
        pass  # Homepage module not available
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
