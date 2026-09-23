import argparse
import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .auth import AuthAnalyzer
from .extractors import ExtractorAnalyzer
from .headers import HeaderAnalyzer
from .parser import EmailParser
from .scoring import ScoringEngine


def get_risk_color(risk_level):
    return {
        "SAFE": "green",
        "SUSPICIOUS": "yellow",
        "HIGH_RISK": "orange3",
        "CRITICAL": "red bold",
    }.get(risk_level.value, "white")


def create_parser():
    parser = argparse.ArgumentParser(
        prog="phishscope", description="PhishScope: Static Analysis for Email Phishing"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze an .eml file")
    analyze_parser.add_argument("file", type=str, help="Path to the .eml file")
    analyze_parser.add_argument("--json", action="store_true", help="Output final results as JSON")

    # Detect command (future)
    detect_parser = subparsers.add_parser("detect", help="Run Sigma detection rules")
    detect_parser.add_argument("file", type=str, help="Path to the .eml file", nargs="?")
    detect_parser.add_argument("--rules", type=str, help="Path to rules", default=None)
    detect_parser.add_argument("--logs", type=str, help="Path to logs", default=None)
    return parser

def main():
    parser = create_parser()

    try:
        args = parser.parse_args()
    except SystemExit as e:
        return e.code

    if args.command == "analyze":
        console = Console(quiet=args.json)

        file_path = Path(args.file)
        if not file_path.exists():
            console.print(f"[red]Error: File {file_path} does not exist.[/red]")
            return 1

        console.print(f"Analyzing: [bold]{file_path}[/bold]\n")

        parser_obj = EmailParser()
        email = parser_obj.parse_file(str(file_path))

        console.print("[green]Parsing Successful![/green]")
        console.print(f"From: {email.from_header}")
        console.print(f"To: {email.to_headers}")
        console.print(f"Subject: {email.subject}")
        console.print(f"Date: {email.date}")
        console.print(f"Message-ID: {email.message_id}")
        console.print(f"Reply-To: {email.reply_to}")
        console.print(f"Return-Path: {email.return_path}\n")

        console.print(f"Received headers: {len(email.received_headers)}")
        types = []
        if email.body_plain:
            types.append("text/plain")
        if email.body_html:
            types.append("text/html")
        console.print(f"Body types: {', '.join(types)}")
        console.print(f"Attachments: {len(email.attachments)}\n")

        findings = []

        console.print("Analyzing Headers...")
        hdr_analyzer = HeaderAnalyzer()
        findings.extend(hdr_analyzer.analyze(email))

        console.print("Analyzing Body & Attachments...")
        ext_analyzer = ExtractorAnalyzer()
        ext_findings, unique_urls = ext_analyzer.analyze(email)
        findings.extend(ext_findings)

        console.print("Analyzing Authentication...")
        auth_analyzer = AuthAnalyzer()
        auth_findings, auth_hdrs = auth_analyzer.analyze(email)
        findings.extend(auth_findings)

        console.print(f"Authentication Headers Parsed: {len(auth_hdrs)}")
        for hdr in auth_hdrs:
            console.print(f"  - {hdr.header_name} (Server: {hdr.server_id})")

        console.print(f"Extracted Unique URLs: {len(unique_urls)}")
        for u in unique_urls:
            console.print(f"  - {u.defanged} (Source: {u.source})")

        console.print("\n")

        # Table Output (Hidden if JSON is requested)
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Category", style="dim")
        table.add_column("Severity")
        table.add_column("Finding")
        table.add_column("Evidence")

        for f in findings:
            table.add_row(f.category.name, str(f.severity), f.name, f.evidence)

        console.print(table)
        console.print("\n")

        # Scoring
        scoring_engine = ScoringEngine()
        result = scoring_engine.evaluate(findings)

        if args.json:
            out_dict = {
                "risk_score": result.score,
                "risk_level": result.risk_level.value,
                "assessment_confidence": result.assessment_confidence.value,
                "category_breakdown": {
                    cat.name: {
                        "raw_score": round(cs.raw_score, 2),
                        "capped_score": round(cs.capped_score, 2),
                        "findings": [
                            {
                                "id": f.id,
                                "name": f.name,
                                "severity": f.severity.value,
                                "confidence": f.confidence.value,
                                "evidence": f.evidence,
                                "description": f.description,
                            }
                            for f in cs.contributing_findings
                        ],
                    }
                    for cat, cs in result.category_scores.items()
                },
            }
            # Output raw JSON to stdout so it can be piped easily
            print(json.dumps(out_dict, indent=2))
        else:
            # Rich Scoring Panel
            risk_color = get_risk_color(result.risk_level)

            panel_content = (
                f"Risk Level:         [{risk_color}]{result.risk_level.value}[/{risk_color}]\n"
            )
            panel_content += f"Risk Score:         {result.score} / 100\n"
            panel_content += f"Assessment Conf:    {result.assessment_confidence.value}\n\n"
            panel_content += "[bold]SCORING BREAKDOWN[/bold]\n"

            for cat_name in ["AUTHENTICATION", "URL", "HEADER", "ATTACHMENT"]:
                cat_enum = next(
                    (c for c in result.category_scores.keys() if c.name == cat_name), None
                )
                if cat_enum:
                    cs = result.category_scores[cat_enum]
                    cap = scoring_engine.category_caps.get(cat_enum, 100)
                    is_capped = " (Capped)" if cs.raw_score > cap else ""
                    cat_label = cat_name.capitalize().ljust(15)
                    panel_content += (
                        f"  {cat_label}: {round(cs.capped_score, 1)} / {cap}{is_capped}\n"
                    )

            console.print(
                Panel(panel_content, title="[bold]PHISHSCOPE ANALYSIS[/bold]", border_style="blue")
            )

    elif args.command == "detect":
        print("Sigma detection not yet implemented.")

    return 0


if __name__ == "__main__":
    main()
