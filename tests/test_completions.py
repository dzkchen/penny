from __future__ import annotations

import penny.repl_input as repl_input
from penny.completions import (
    SLASH_COMPLETIONS,
    apply_tab_completion,
    completions_for_buffer,
    ghost_suffix,
    suggestion_lines,
)
import penny.completions as slash


def test_completions_only_after_slash() -> None:
    assert completions_for_buffer("audit") == []
    assert completions_for_buffer("/") == list(SLASH_COMPLETIONS)


def test_completions_filter_by_prefix() -> None:
    matches = completions_for_buffer("/sc")
    assert [item.name for item in matches] == ["scan"]
    matches = completions_for_buffer("/a")
    names = {item.name for item in matches}
    assert "audit" in names
    assert "ai" in names


def test_completions_include_aliases() -> None:
    matches = completions_for_buffer("/fu")
    assert matches and matches[0].name == "audit"


def test_completions_include_sandbox_commands() -> None:
    names = {item.name for item in completions_for_buffer("/sandbox")}
    assert names == {"sandbox-bake", "sandbox-test"}
    assert [item.name for item in completions_for_buffer("/sandbox-t")] == ["sandbox-test"]


def test_tab_completes_unique_command() -> None:
    matches = completions_for_buffer("/sc")
    assert apply_tab_completion("/sc", matches) == "/scan "


def test_tab_completes_highlighted_ambiguous_command() -> None:
    matches = completions_for_buffer("/a")
    assert apply_tab_completion("/a", matches) == f"/{matches[0].name} "


def test_tab_uses_selected_suggestion() -> None:
    matches = completions_for_buffer("/a")
    selected = next(index for index, item in enumerate(matches) if item.name == "ai")
    assert apply_tab_completion("/a", matches, selected=selected) == "/ai "


def test_ghost_suffix_shows_remaining_command_name() -> None:
    matches = completions_for_buffer("/au")
    assert ghost_suffix("/au", matches).startswith("dit")


def test_suggestion_lines_highlight_first_match() -> None:
    matches = completions_for_buffer("/sc")
    lines = suggestion_lines(matches, selected=0, width=120)
    assert lines[0].startswith("› /scan")
    assert "scan only" in lines[0]


def test_completions_hide_after_command_args() -> None:
    assert completions_for_buffer("/audit ./planted-app") == []


def test_autocomplete_disabled_without_tty(monkeypatch) -> None:
    import pytest

    pytest.importorskip("prompt_toolkit")
    monkeypatch.delenv("PENNY_NO_AUTOCOMPLETE", raising=False)
    monkeypatch.setattr(repl_input.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(repl_input.sys.stdout, "isatty", lambda: True)
    assert repl_input.autocomplete_enabled() is False


def test_autocomplete_requires_prompt_toolkit(monkeypatch) -> None:
    monkeypatch.delenv("PENNY_NO_AUTOCOMPLETE", raising=False)
    monkeypatch.setattr(repl_input.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(repl_input.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(repl_input, "_CompleterBase", None)
    assert repl_input.autocomplete_enabled() is False


def test_slash_completer_yields_matches() -> None:
    import pytest

    pytest.importorskip("prompt_toolkit")
    from prompt_toolkit.document import Document

    completer = repl_input._make_completer()
    completions = list(completer.get_completions(Document("/au"), None))
    assert completions
    assert completions[0].text.startswith("dit")


def test_completion_parts_replaces_partial_token() -> None:
    import pytest

    pytest.importorskip("prompt_toolkit")
    item = next(item for item in slash.SLASH_COMPLETIONS if item.name == "audit")
    insert, start = repl_input._completion_parts("/fu", item)
    assert insert == "audit "
    assert start == -2


def test_autocomplete_disabled_by_env(monkeypatch) -> None:
    monkeypatch.setenv("PENNY_NO_AUTOCOMPLETE", "1")
    monkeypatch.setattr(repl_input.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(repl_input.sys.stdout, "isatty", lambda: True)
    assert repl_input.autocomplete_enabled() is False


def test_clear_screen_writes_escape_to_real_stdout(monkeypatch) -> None:
    import io

    fake = io.StringIO()
    # Force the raw-ANSI fallback and confirm it targets the real stdout,
    # not prompt_toolkit's patched proxy (the cause of the /clear regression).
    monkeypatch.setattr(repl_input, "_CompleterBase", None)
    monkeypatch.setattr(repl_input.sys, "__stdout__", fake)
    repl_input.clear_screen()
    assert "\x1b[2J" in fake.getvalue()
