"""Command-line interface for evidence-sanitizer."""

import typer

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
    """Show root help for the Milestone 0 CLI skeleton."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=0)


def main() -> None:
    """Run the evidence-sanitizer CLI."""
    app()
