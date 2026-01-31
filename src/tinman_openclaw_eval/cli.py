"""CLI for tinman-openclaw-eval."""

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

from .harness import EvalHarness
from .synthetic_gateway import SyntheticGateway, GatewayConfig, GatewayMode
from .report import ReportGenerator
from .attacks import AttackCategory, Severity


console = Console()


@click.group()
@click.version_option(version="0.1.0")
def main():
    """Tinman OpenClaw Eval - Security evaluation harness for AI agents."""
    pass


@main.command()
@click.option("--category", "-c", multiple=True, help="Filter by category")
@click.option("--severity", "-s", default="S1", help="Minimum severity (S0-S4)")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--format", "-f", type=click.Choice(["markdown", "json", "sarif", "junit"]), default="markdown")
@click.option("--gateway-url", help="Real gateway WebSocket URL")
@click.option("--mock/--no-mock", default=True, help="Use mock gateway (default: true)")
@click.option("--concurrent", default=5, help="Max concurrent attacks")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def run(category, severity, output, format, gateway_url, mock, concurrent, verbose):
    """Run security evaluation."""
    console.print("[bold blue]Tinman OpenClaw Eval[/bold blue]")
    console.print()

    # Configure gateway
    config = GatewayConfig(
        mode=GatewayMode.MOCK if mock else GatewayMode.PROXY,
        real_gateway_url=gateway_url or "ws://127.0.0.1:18789",
    )
    gateway = SyntheticGateway(config)
    harness = EvalHarness(gateway)

    # Get payloads
    payloads = harness.get_all_payloads()

    # Apply filters
    if category:
        categories = [AttackCategory(c) for c in category]
        payloads = [p for p in payloads if p.category in categories]

    if severity:
        sev = Severity(severity)
        severity_order = [Severity.S0, Severity.S1, Severity.S2, Severity.S3, Severity.S4]
        min_index = severity_order.index(sev)
        payloads = [p for p in payloads if severity_order.index(p.severity) >= min_index]

    console.print(f"Running {len(payloads)} attacks...")
    console.print()

    # Run with progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("Executing attacks", total=len(payloads))

        def on_progress(completed, total):
            progress.update(task, completed=completed)

        result = asyncio.run(
            harness.run(
                payloads=payloads,
                max_concurrent=concurrent,
                progress_callback=on_progress,
            )
        )

    console.print()

    # Show summary
    summary = result.summary()
    table = Table(title="Results Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Total Attacks", str(summary["total_attacks"]))
    table.add_row("Passed", str(summary["passed"]))
    table.add_row("Failed", str(summary["failed"]))
    table.add_row("Vulnerabilities", f"[red bold]{summary['vulnerabilities']}[/red bold]")
    table.add_row("Pass Rate", summary["pass_rate"])

    console.print(table)
    console.print()

    # Show vulnerabilities
    vulns = [r for r in result.results if r.is_vulnerability]
    if vulns:
        console.print("[red bold]Vulnerabilities Found:[/red bold]")
        for v in vulns:
            console.print(f"  [{v.severity.value}] {v.attack_id}: {v.attack_name}")
        console.print()

    # Generate report
    if output:
        report = ReportGenerator(result)
        report.save(output, format)
        console.print(f"Report saved to: {output}")
    else:
        # Print to stdout
        report = ReportGenerator(result)
        if format == "json":
            click.echo(report.to_json())
        elif verbose:
            click.echo(report.to_markdown())

    # Exit with error if vulnerabilities found
    if result.vulnerabilities > 0:
        sys.exit(1)


@main.command()
@click.argument("result_file", type=click.Path(exists=True))
@click.option("--baseline", "-b", type=click.Path(exists=True), required=True)
def assert_cmd(result_file, baseline):
    """Assert results match baseline."""
    console.print("[bold blue]Asserting against baseline...[/bold blue]")

    # Load result
    with open(result_file) as f:
        data = json.load(f)

    # Reconstruct EvalResult (simplified)
    from .harness import EvalResult
    from .attacks import AttackResult, ExpectedBehavior
    from datetime import datetime

    result = EvalResult(
        run_id=data["run_id"],
        started_at=datetime.fromisoformat(data["started_at"]),
        completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
        total_attacks=data["summary"]["total_attacks"],
        passed=data["summary"]["passed"],
        failed=data["summary"]["failed"],
        vulnerabilities=data["summary"]["vulnerabilities"],
        results=[
            AttackResult(
                attack_id=r["attack_id"],
                attack_name=r["attack_name"],
                category=AttackCategory(r["category"]),
                severity=Severity(r["severity"]),
                expected=ExpectedBehavior(r["expected"]),
                actual=ExpectedBehavior(r["actual"]),
                passed=r["passed"],
            )
            for r in data["results"]
        ],
    )

    harness = EvalHarness()
    passed, differences = harness.assert_baseline(result, baseline)

    if passed:
        console.print("[green]All assertions passed![/green]")
        sys.exit(0)
    else:
        console.print("[red]Baseline assertion failed:[/red]")
        for diff in differences:
            console.print(f"  - {diff}")
        sys.exit(1)


@main.command()
@click.option("--output", "-o", type=click.Path(), required=True)
def baseline(output):
    """Generate baseline from current run."""
    console.print("[bold blue]Generating baseline...[/bold blue]")

    harness = EvalHarness()
    result = asyncio.run(harness.run())

    harness.save_baseline(result, output)
    console.print(f"Baseline saved to: {output}")


@main.command()
def list_attacks():
    """List all available attacks."""
    harness = EvalHarness()
    payloads = harness.get_all_payloads()

    table = Table(title=f"Available Attacks ({len(payloads)} total)")
    table.add_column("ID", style="cyan")
    table.add_column("Category", style="yellow")
    table.add_column("Severity", style="red")
    table.add_column("Name")

    for p in payloads:
        table.add_row(
            p.id,
            p.category.value,
            p.severity.value,
            p.name,
        )

    console.print(table)


@main.command()
@click.argument("attack_id")
@click.option("--verbose", "-v", is_flag=True)
def run_single(attack_id, verbose):
    """Run a single attack by ID."""
    console.print(f"[bold blue]Running attack: {attack_id}[/bold blue]")

    harness = EvalHarness()

    try:
        result = asyncio.run(harness.run_single(attack_id))
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    # Display result
    status = "[green]PASSED[/green]" if result.passed else "[red]FAILED[/red]"
    if result.is_vulnerability:
        status = "[red bold]VULNERABILITY[/red bold]"

    console.print()
    console.print(f"Status: {status}")
    console.print(f"Expected: {result.expected.value}")
    console.print(f"Actual: {result.actual.value}")
    console.print(f"Latency: {result.latency_ms:.1f}ms")

    if verbose and result.response:
        console.print()
        console.print("Response:")
        console.print(result.response[:500])

    if result.error:
        console.print(f"[yellow]Error: {result.error}[/yellow]")


if __name__ == "__main__":
    main()
