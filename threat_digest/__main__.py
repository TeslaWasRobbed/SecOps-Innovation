"""CLI entry point: python -m threat_digest"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import anthropic
from rich.console import Console

from shared.output import print_panel, save_markdown
from threat_digest.dashboard import update_digest_dashboard
from threat_digest.digest import build_digest
from threat_digest.html_report import build_digest_html, generate_pdf
from threat_digest.profile import load_company_profile, resolve_profile_path

console = Console()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a stakeholder-friendly threat digest with retry logic, duplicate detection, and PDF export."
    )
    parser.add_argument("--days", type=int, default=7, help="Look-back window in days (default: 7)")
    parser.add_argument(
        "--output-dir",
        default="output/threat_digest",
        help="Directory for markdown output (default: output/threat_digest)",
    )
    parser.add_argument(
        "--no-claude",
        action="store_true",
        help="Skip LLM: CISA KEV + RSS only (no Azure OpenAI / Anthropic)",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Same as --no-claude: feeds only, no LLM",
    )
    parser.add_argument(
        "--profile",
        default=None,
        metavar="PATH",
        help="YAML company profile (default: COMPANY_PROFILE env or ./company_profile.yaml if present)",
    )
    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Skip writing stakeholder HTML (markdown only)",
    )
    parser.add_argument(
        "--pdf",
        action="store_true",
        help="Generate PDF export in addition to HTML (requires weasyprint)",
    )
    args = parser.parse_args(argv)
    skip_claude = args.no_claude or args.no_llm

    profile_path = resolve_profile_path(args.profile)
    if args.profile and profile_path is None:
        console.print(f"[yellow]Profile file not found:[/yellow] {args.profile} — continuing without profile.\n")
    company_profile = load_company_profile(profile_path)
    if company_profile and profile_path:
        console.print(f"[dim]Using organisation profile:[/dim] {profile_path}\n")

    console.print("\n[bold cyan]Threat Digest[/bold cyan] — fetching intelligence...\n")

    try:
        result = build_digest(
            days=args.days,
            use_llm=not skip_claude,
            company_profile=company_profile,
        )
    except RuntimeError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        console.print("\n[dim]Troubleshooting tips:[/dim]")
        console.print("• Check network connectivity")
        console.print("• Verify RSS feed URLs are accessible")
        console.print("• Try running with [bold]--no-llm[/bold] for feed-only mode")
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
            "You can still generate a feed-only digest (no LLM):\n"
            "  [bold]python -m threat_digest --no-llm[/bold]\n"
        )
        return 1
    except anthropic.APIConnectionError as exc:
        console.print(f"[bold red]Cannot reach Anthropic API:[/bold red] {exc}\n")
        console.print("Try [bold]python -m threat_digest --no-llm[/bold] for a feed-only digest.\n")
        return 1
    except Exception as exc:
        if getattr(type(exc), "__module__", "").startswith("openai"):
            console.print(f"[bold red]Azure OpenAI / OpenAI SDK error:[/bold red] {exc}\n")
            console.print(
                "Check VPN, `.env` (`AZURE_OPENAI_*`), and corporate TLS (`LLM_CA_BUNDLE`). "
                "Feed-only mode:\n  [bold]python -m threat_digest --no-llm[/bold]\n"
            )
            return 1
        raise

    mode = "LLM summary" if result.get("used_llm") == "true" else "raw feeds only"
    prof = " | profile" if result.get("profile_loaded") == "true" else ""
    stats = f"{result['kev_count']} KEVs | {result['article_count']} articles | last {args.days} days | {mode}{prof}"
    if not skip_claude and result.get("used_llm") != "true":
        console.print(
            "[yellow]LLM did not return a usable summary[/yellow] (empty output, refusal, or token limit). "
            "Wrote feed-only digest instead. For reasoning models, set [bold]DIGEST_MAX_COMPLETION_TOKENS[/bold] "
            "in `.env` (default in code is 16384).\n"
        )
    print_panel("Threat Digest", result["summary"], subtitle=stats, style="bold cyan")

    datestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    save_markdown(
        args.output_dir,
        f"digest_{datestamp}.md",
        f"Threat Digest — {datestamp}",
        result["summary"],
        paste_friendly=skip_claude,
    )

    if not args.no_html:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        html_path = out_dir / f"digest_{datestamp}.html"
        html_doc = build_digest_html(
            summary_markdown=result["summary"],
            profile=company_profile,
            datestamp=datestamp,
            days=args.days,
            kev_count=int(result["kev_count"]),
            article_count=int(result["article_count"]),
            used_llm=result.get("used_llm") == "true",
            digest_payload=result.get("digest_payload"),
            watchlist=result.get("watchlist"),
        )
        html_path.write_text(html_doc, encoding="utf-8")
        console.print(f"[dim]Saved HTML -> {html_path}[/dim]")

        dashboard_path = update_digest_dashboard(out_dir, html_path)
        console.print(f"[dim]Updated dashboard -> {dashboard_path}[/dim]")
        
        # Auto-update actor tracking data
        try:
            from shared.actor_tracking import update_actor_tracking
            console.print("[dim]Updating actor tracking data...[/dim]")
            tracking_data = update_actor_tracking()
            total_mentions = sum(actor.get('total_mentions', 0) for actor in tracking_data.get('actors', {}).values())
            if total_mentions > 0:
                console.print(f"[dim]Found {total_mentions} actor mentions across digests[/dim]")
            try:
                from actor_watch.dashboard import generate_actor_dashboard

                actor_dashboard = generate_actor_dashboard(Path("output/actor_watch") / "index.html", args.days)
                console.print(f"[dim]Updated Actor Watch -> {actor_dashboard}[/dim]")
            except Exception as e:
                console.print(f"[yellow]Could not update Actor Watch dashboard: {e}[/yellow]")
        except ImportError:
            pass  # Actor tracking module not available
        except Exception as e:
            console.print(f"[yellow]Could not update actor tracking: {e}[/yellow]")
        
        # Auto-update homepage
        try:
            from shared.auto_update import update_homepage_after_generation
            update_homepage_after_generation("threat_digest", html_path.name)
        except ImportError:
            pass  # Homepage module not available
        
        # Generate PDF if requested
        if args.pdf:
            pdf_path = out_dir / f"digest_{datestamp}.pdf"
            console.print("[dim]Generating PDF...[/dim]")
            
            if generate_pdf(html_doc, pdf_path):
                console.print(f"[dim]Saved PDF -> {pdf_path}[/dim]")
            else:
                console.print("[yellow]PDF generation failed. Install weasyprint: pip install weasyprint[/yellow]")

    return 0


if __name__ == "__main__":
    sys.exit(main())
