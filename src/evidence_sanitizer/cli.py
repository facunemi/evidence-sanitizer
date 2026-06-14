"""Command-line interface for evidence-sanitizer."""

from pathlib import Path
from typing import Annotated

import typer

from evidence_sanitizer.sanitizer import SafeError, SanitizationReport, sanitize_file

PRODUCT_DESCRIPTION = (
    "Local-first CLI for creating sanitized copies of authorized "
    "penetration-testing evidence."
)

app = typer.Typer(
    add_completion=False,
    help=PRODUCT_DESCRIPTION,
    invoke_without_command=True,
    no_args_is_help=False,
)


@app.callback()
def root(ctx: typer.Context) -> None:
    """Show root help when no command is provided."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=0)


@app.command()
def sanitize(
    input_path: Annotated[Path, typer.Argument(metavar="INPUT")],
    output_path: Annotated[Path, typer.Option("--output", metavar="OUTPUT")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Create a sanitized copy of one evidence text file."""
    try:
        result = sanitize_file(input_path, output_path, dry_run=dry_run)
    except SafeError as error:
        typer.echo(f"Error: {error.message}", err=True)
        raise typer.Exit(code=error.exit_code) from error
    except Exception as exc:
        typer.echo("Error: unexpected internal error", err=True)
        raise typer.Exit(code=1) from exc

    if dry_run:
        typer.echo("Dry run: no output written")
    else:
        typer.echo(f"Sanitized: {input_path} -> {output_path}")
    _render_report(result.report)


def _render_report(report: SanitizationReport) -> None:
    if not report.counts_by_rule:
        typer.echo("Rules triggered: none")
        return

    typer.echo("Rules triggered:")
    for rule_id in sorted(report.counts_by_rule):
        typer.echo(f"{rule_id}: {report.counts_by_rule[rule_id]}")


def main() -> None:
    """Run the evidence-sanitizer CLI."""
    app()
