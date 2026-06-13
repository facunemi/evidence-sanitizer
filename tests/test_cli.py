"""Behavioral tests for the Milestone 0 CLI skeleton."""

import subprocess
import sys
from collections.abc import Sequence

PRODUCT_DESCRIPTION = (
    "Local-first CLI for creating sanitized copies of authorized "
    "penetration-testing evidence."
)
ENTRYPOINTS = ("console", "module")


def run_entrypoint(
    entrypoint: str, args: Sequence[str]
) -> subprocess.CompletedProcess[str]:
    if entrypoint == "console":
        command = ["evidence-sanitizer", *args]
    elif entrypoint == "module":
        command = [sys.executable, "-m", "evidence_sanitizer", *args]
    else:
        raise ValueError(f"unknown test entry point: {entrypoint}")

    return subprocess.run(command, capture_output=True, text=True, check=False)


def combined_output(result: subprocess.CompletedProcess[str]) -> str:
    return result.stdout + result.stderr


def normalize_whitespace(text: str) -> str:
    return " ".join(text.split())


def assert_help_displayed(result: subprocess.CompletedProcess[str]) -> None:
    output = combined_output(result)
    assert result.returncode == 0, output
    assert PRODUCT_DESCRIPTION in normalize_whitespace(output)
    assert "--help" in output


def assert_rejected(
    result: subprocess.CompletedProcess[str], expected_text: str
) -> None:
    output = combined_output(result)
    assert result.returncode != 0, output
    assert expected_text in output


def assert_unknown_command(
    result: subprocess.CompletedProcess[str], command_name: str
) -> None:
    output = combined_output(result)
    assert_rejected(result, command_name)
    assert "No such command" in output


def test_root_help_exits_zero_and_contains_description() -> None:
    for entrypoint in ENTRYPOINTS:
        assert_help_displayed(run_entrypoint(entrypoint, ["--help"]))


def test_console_script_and_module_help_are_consistent() -> None:
    console_result = run_entrypoint("console", ["--help"])
    module_result = run_entrypoint("module", ["--help"])

    assert console_result.returncode == module_result.returncode == 0
    for result in (console_result, module_result):
        output = combined_output(result)
        assert PRODUCT_DESCRIPTION in normalize_whitespace(output)
        assert "--help" in output


def test_no_argument_execution_displays_help_and_exits_zero() -> None:
    for entrypoint in ENTRYPOINTS:
        assert_help_displayed(run_entrypoint(entrypoint, []))


def test_sanitize_is_rejected_as_unknown_command() -> None:
    for entrypoint in ENTRYPOINTS:
        assert_unknown_command(run_entrypoint(entrypoint, ["sanitize"]), "sanitize")


def test_milestone_one_options_are_not_accepted() -> None:
    for entrypoint in ENTRYPOINTS:
        for option in ("--output", "--dry-run"):
            assert_rejected(run_entrypoint(entrypoint, [option]), option)
