"""vault-pull's decrypt step undoes its own header rewrite when the decrypt fails.

With ``--env-file`` it rewrites the custom file's dotenvx header before the decrypt, so
the backend's own snapshot holds the rewritten header. The real-binary proof is
``test_vault_pull_env_file_failure_puts_back_the_header_too`` in
``tests/integration/test_decrypt_failure_e2e.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import typer

from tests.helpers import unreadable_file


def _undo(target: Path, before: bytes | None) -> str:
    """``_undo_header_rewrite``, imported here so this module collects against code
    without it."""
    from envdrift.cli_commands.vault_helpers import _undo_header_rewrite

    return _undo_header_rewrite(target, before)


class TestUndoHeaderRewrite:
    def test_nothing_to_undo_without_a_rewrite(self, tmp_path: Path) -> None:
        target = tmp_path / "custom.env"
        target.write_bytes(b"K=v\n")

        assert _undo(target, None) == ""
        assert target.read_bytes() == b"K=v\n"

    def test_the_bytes_before_the_rewrite_are_put_back(self, tmp_path: Path) -> None:
        target = tmp_path / "custom.env"
        target.write_bytes(b"# .env.production\nK=v\n")  # rewritten, LF

        assert _undo(target, b"# custom.env\r\nK=v\r\n") == ""
        assert target.read_bytes() == b"# custom.env\r\nK=v\r\n"  # CRLF too

    def test_a_put_back_that_fails_is_reported(self, tmp_path: Path) -> None:
        target = tmp_path / "custom.env"
        target.mkdir()  # reading or writing it fails, as a real OSError

        assert _undo(target, b"# custom.env\n").startswith(
            f"\nenvdrift could not put back the dotenvx header it rewrote in {target}: "
        )


def test_an_unreadable_target_is_an_error_not_a_traceback(
    searchable_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from envdrift.cli_commands import vault_helpers
    from envdrift.encryption import EncryptionProvider

    target = searchable_tmp_path / "custom.env"
    target.write_text("# custom.env\nK=encrypted:BAAA\n", encoding="utf-8")
    # The backend is never reached: the target is refused before it.
    monkeypatch.setattr(
        vault_helpers,
        "_resolve_pull_backend",
        lambda _config: (object(), EncryptionProvider.DOTENVX),
    )
    request = vault_helpers.VaultPullRequest(
        folder=searchable_tmp_path,
        secret_name="unused",
        environment="production",
        connection=vault_helpers.VaultConnectionOptions(
            config=None, provider=None, vault_url=None, region=None, project_id=None
        ),
        no_decrypt=False,
        env_file=Path("custom.env"),
    )

    with unreadable_file(target), pytest.raises(typer.Exit) as excinfo:
        vault_helpers._decrypt_pull_target(request, target, searchable_tmp_path / ".env.keys")

    captured = capsys.readouterr().err
    err = " ".join(captured.split())
    assert excinfo.value.exit_code == 1, err
    # Rich breaks a path longer than the console inside the path (a macOS temp path
    # was), so the path is compared with every space and line break taken out.
    expected = f"Failed to decrypt {target}: [Errno 13]"
    assert "".join(expected.split()) in "".join(captured.split()), err
    assert "Nothing was decrypted." in err, err
