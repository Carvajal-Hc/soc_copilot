from __future__ import annotations

import pytest

from soc_copilot import cli
from soc_copilot.config import ENV_TOKEN


def test_render_table_lists_every_column() -> None:
    rows = [
        {"Computer": "DESKTOP-01", "EventId": "4624", "count": "120"},
        {"Computer": "DESKTOP-02", "EventId": "4688", "count": "97"},
    ]
    out = cli.render_table(rows, ["Computer", "EventId", "count"])
    assert "DESKTOP-01" in out and "4688" in out
    assert out.splitlines()[0].split() == ["Computer", "EventId", "count"]


def test_render_table_limits_and_says_so() -> None:
    rows = [{"n": str(i)} for i in range(10)]
    out = cli.render_table(rows, limit=3)
    assert "7 more row(s) not shown" in out


def test_render_table_handles_no_rows() -> None:
    assert cli.render_table([]) == "(no rows)"


def test_render_table_infers_columns_from_rows() -> None:
    out = cli.render_table([{"a": 1}, {"b": 2}])
    assert out.splitlines()[0].split() == ["a", "b"]


def test_verify_spl_is_the_documented_query() -> None:
    assert (
        cli.VERIFY_SPL.format(index="logforge")
        == "index=logforge | stats count by Computer, EventId"
    )


def test_defaults_are_all_time_and_logforge() -> None:
    args = cli.build_parser().parse_args([])
    assert args.index == "logforge"
    assert args.earliest == "0"
    assert args.latest == ""
    assert args.command is None  # falls through to `verify`


def test_missing_token_exits_with_guidance(capsys, monkeypatch) -> None:
    monkeypatch.delenv(ENV_TOKEN, raising=False)
    # Point .env discovery at a directory with no .env in it.
    monkeypatch.setattr(cli, "load_config", _raise_config_error)

    assert cli.main(["verify"]) == 2
    err = capsys.readouterr().err
    assert "Configuration error" in err
    assert "Settings > Tokens" in err


def _raise_config_error(*args: object, **kwargs: object):
    from soc_copilot.config import MISSING_TOKEN_MESSAGE, ConfigError

    raise ConfigError(MISSING_TOKEN_MESSAGE)


@pytest.mark.parametrize(
    ("value", "expected"), [("120", 120), ("12.0", 12), (None, 0), ("", 0), ("x", 0)]
)
def test_to_int_is_forgiving(value: object, expected: int) -> None:
    assert cli._to_int(value) == expected


# --------------------------------------------------------------------------
# Stage 4 — views and the auth failure at the top level
# --------------------------------------------------------------------------


def test_view_defaults_to_human_and_accepts_the_other_two() -> None:
    parser = cli.build_parser()

    assert parser.parse_args(["investigate", "q"]).view == "human"
    assert parser.parse_args(["investigate", "--view", "spl", "q"]).view == "spl"
    assert parser.parse_args(["investigate", "--view", "json", "q"]).view == "json"


def test_the_older_json_flag_still_selects_the_json_view() -> None:
    args = cli.build_parser().parse_args(["investigate", "--json", "q"])

    assert cli._resolve_view(args) == "json"


def test_an_unknown_view_is_rejected_by_the_parser() -> None:
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["investigate", "--view", "yaml", "q"])


def test_only_the_human_view_streams_the_transcript() -> None:
    parse = cli.build_parser().parse_args

    assert cli._streams_transcript(parse(["investigate", "q"]))
    assert not cli._streams_transcript(parse(["investigate", "--view", "spl", "q"]))
    assert not cli._streams_transcript(parse(["investigate", "--view", "json", "q"]))


def test_setup_chatter_stays_off_stdout_in_the_machine_views(capsys) -> None:
    """A preamble mixed into --view json would make it unparseable."""
    cli._noter("json")("connecting")
    cli._noter("human")("connecting")

    captured = capsys.readouterr()
    assert captured.out.strip() == "connecting"
    assert captured.err.strip() == "connecting"


def test_a_rejected_token_exits_with_guidance_not_a_traceback(capsys, monkeypatch) -> None:
    """HTTP 401 anywhere under a command surfaces as the actionable message."""
    from soc_copilot.config import SplunkConfig
    from soc_copilot.splunk_client import AUTH_FAILURE_MESSAGE, SplunkAuthError

    monkeypatch.setattr(
        cli,
        "load_config",
        lambda *a, **k: SplunkConfig(
            host="https://localhost:8089",
            token="expired",
            verify_tls=False,
            is_local=True,
        ),
    )

    def _reject(client: object, args: object) -> int:
        raise SplunkAuthError(AUTH_FAILURE_MESSAGE)

    monkeypatch.setitem(cli.__dict__, "cmd_verify", _reject)

    assert cli.main(["verify"]) == 1
    err = capsys.readouterr().err
    assert "HTTP 401" in err
    assert "Settings > Tokens" in err
    assert "Traceback" not in err
