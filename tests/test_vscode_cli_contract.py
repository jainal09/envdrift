"""Contract tests between the VS Code extension and the real CLIs (#482).

The extension shells out to two binaries it does not own: the ``envdrift``
Python CLI and the ``envdrift-agent`` Go binary. Issue #482 was a cluster of
argv mismatches (``envdrift lock <file>`` — lock takes no positional;
``envdrift-agent --version`` — the agent only has a ``version`` subcommand)
that made every core feature structurally dead while the UI showed success.

These tests extract the argv the extension actually spawns from its TypeScript
source and validate each one against the real binaries, so the contract can
never silently rot again.
"""

from __future__ import annotations

import json
import os
import re
import runpy
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
VSCODE_DIR = REPO_ROOT / "envdrift-vscode"
VSCODE_SRC = VSCODE_DIR / "src"
AGENT_DIR = REPO_ROOT / "envdrift-agent"

# CSI sequences (colors/styles) and OSC sequences (terminal hyperlinks).
_ANSI_ESCAPES = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def _plain(text: str) -> str:
    """Normalize CLI output: strip ANSI escapes, collapse whitespace.

    Typer's help renderer forces rich styling whenever ``GITHUB_ACTIONS``,
    ``FORCE_COLOR`` or ``PY_COLORS`` is set, and ``NO_COLOR`` only drops
    colors — bold/dim codes still land inside phrases like ``Usage:`` on CI.
    Assertions must always compare plain text.
    """
    return " ".join(_ANSI_ESCAPES.sub("", text).split())


def _clean_env(**overrides: str) -> dict[str, str]:
    """Subprocess env: a copy of os.environ with colorization disabled.

    CI exports ``FORCE_COLOR=1`` and ``GITHUB_ACTIONS=true``; either one makes
    Typer/Rich force terminal styling even into a pipe (``FORCE_COLOR`` also
    overrides ``NO_COLOR`` in Rich). Strip them all and pin a wide terminal so
    help output is stable and grep-able.
    """
    env = os.environ.copy()
    for var in ("FORCE_COLOR", "GITHUB_ACTIONS", "PY_COLORS"):
        env.pop(var, None)
    env["NO_COLOR"] = "1"
    env["COLUMNS"] = "200"
    env.update(overrides)
    return env


def _envdrift_cmd() -> list[str]:
    """Command prefix for the real envdrift CLI."""
    exe = shutil.which("envdrift")
    if exe:
        return [exe]
    return [sys.executable, "-m", "envdrift"]


def _extension_sources() -> list[Path]:
    """All non-test TypeScript sources of the extension."""
    return [p for p in VSCODE_SRC.rglob("*.ts") if "test" not in p.parts]


def _extension_envdrift_subcommand() -> str:
    """Extract the envdrift subcommand encryption.ts spawns per closed file."""
    src = (VSCODE_SRC / "encryption.ts").read_text(encoding="utf-8")
    # The argv is `[...args, 'encrypt', '--', fileName]`; the `--` option
    # terminator is optional so this keeps matching if it is ever dropped.
    match = re.search(r"\[\.\.\.envdriftInfo\.args,\s*'([\w-]+)',\s*(?:'--',\s*)?fileName\]", src)
    assert match, "could not locate the envdrift spawn argv in encryption.ts"
    return match.group(1)


def _extension_agent_commands() -> set[str]:
    """Extract every `envdrift-agent <cmd>` invocation in the extension."""
    commands: set[str] = set()
    for source in _extension_sources():
        for match in re.finditer(
            r"execAsync\(\s*['\"]envdrift-agent ([^'\"]+)['\"]",
            source.read_text(encoding="utf-8"),
        ):
            commands.add(match.group(1).split()[0])
    assert commands, "no envdrift-agent invocations found in extension source"
    return commands


class TestEnvdriftCliContract:
    """The argv encryption.ts spawns must parse on the real envdrift CLI."""

    def test_python_dash_m_envdrift_version(self) -> None:
        """The extension's python fallback probe (`python -m envdrift --version`) works.

        Regression: the package shipped no ``__main__.py``, so the fallback
        could never succeed and pip-installed users were told to reinstall.
        """
        result = subprocess.run(
            [sys.executable, "-m", "envdrift", "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_clean_env(),
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        assert "envdrift" in _plain(result.stdout).lower()

    def test_dunder_main_exposes_cli_app(self) -> None:
        """``envdrift.__main__`` exists and points at the real Typer app."""
        import envdrift.__main__ as dunder_main
        from envdrift.cli import app

        assert dunder_main.app is app

    # runpy warns (benignly) when envdrift.__main__ is already in sys.modules
    # from the import-identity test above; the re-execution is the point here.
    @pytest.mark.filterwarnings("ignore:.*envdrift.__main__.*:RuntimeWarning")
    def test_dunder_main_runs_the_cli_in_process(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Executing ``envdrift.__main__`` as ``__main__`` invokes the Typer app."""
        monkeypatch.setattr(sys, "argv", ["envdrift", "--version"])
        with pytest.raises(SystemExit) as excinfo:
            runpy.run_module("envdrift", run_name="__main__", alter_sys=False)
        assert excinfo.value.code == 0
        assert "envdrift" in _plain(capsys.readouterr().out).lower()

    def test_encrypt_subcommand_takes_positional_env_file(self) -> None:
        """The subcommand the extension spawns accepts a positional ENV_FILE."""
        sub = _extension_envdrift_subcommand()
        result = subprocess.run(
            [*_envdrift_cmd(), sub, "--help"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_clean_env(),
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        usage = _plain(result.stdout)
        # click renders the program name as `envdrift.EXE` on Windows. The
        # positional may be a single `[ENV_FILE]` or a variadic `[ENV_FILES]...`
        # (encrypt accepts multiple files as a pre-commit hook entry, #493); the
        # extension spawns exactly one file, which is valid for either shape.
        pattern = (
            rf"Usage: envdrift(?:\.[Ee][Xx][Ee])? {re.escape(sub)} "
            r"\[OPTIONS\] \[ENV_FILES?\](?:\.\.\.)?"
        )
        assert re.search(pattern, usage), (
            f"`envdrift {sub}` does not take a positional env file — the extension's "
            f"per-file spawn `envdrift {sub} <file>` cannot work. Usage: {usage[:200]}"
        )

    def test_lock_rejects_positional_argument(self, tmp_path: Path) -> None:
        """Documents why the old extension argv (`lock <file>`) always exited 2."""
        env_file = tmp_path / ".env.production"
        env_file.write_text("API_KEY=plain_test_value\n", encoding="utf-8")
        result = subprocess.run(
            [*_envdrift_cmd(), "lock", ".env.production"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=tmp_path,
            env=_clean_env(),
            timeout=60,
        )
        assert result.returncode == 2
        combined = _plain(result.stdout + result.stderr).lower()
        assert "unexpected extra argument" in combined
        assert env_file.read_text(encoding="utf-8") == "API_KEY=plain_test_value\n"

    def test_agent_probe_uses_subcommands_not_flags(self) -> None:
        """The extension must probe the agent with subcommands, never flags.

        Regression: it probed ``envdrift-agent --version``, a flag the cobra
        CLI does not define, so every status check returned "not_installed".
        """
        for command in sorted(_extension_agent_commands()):
            assert not command.startswith("-"), (
                f"extension probes `envdrift-agent {command}` — a flag, not a "
                f"subcommand; the agent CLI only accepts subcommands"
            )


class TestPackagingAndDocsContract:
    """Packaging/docs claims that broke silently in #482."""

    def test_vsix_readme_uses_absolute_docs_links(self) -> None:
        """vsce rewrites monorepo-relative links into 404s; require absolute URLs."""
        readme = (VSCODE_DIR / "README.md").read_text(encoding="utf-8")
        relative_links = re.findall(r"\]\((\.\./[^)]+)\)", readme)
        assert not relative_links, (
            f"vsix README contains monorepo-relative links that 404 on the "
            f"Marketplace after vsce rewriting: {relative_links}"
        )
        assert (
            "https://github.com/jainal09/envdrift/blob/main/docs/guides/vscode-extension.md"
            in readme
        ), "vsix README must link the comprehensive guide with an absolute URL"

    def test_documented_output_channel_is_registered(self) -> None:
        """If docs tell users to check the EnvDrift output channel, it must exist."""
        guide = (REPO_ROOT / "docs" / "guides" / "vscode-extension.md").read_text(encoding="utf-8")
        assert "Output" in guide and "EnvDrift" in guide, (
            "the troubleshooting guide should document the EnvDrift output channel"
        )
        combined_src = "\n".join(p.read_text(encoding="utf-8") for p in _extension_sources())
        assert "createOutputChannel('EnvDrift')" in combined_src, (
            "docs reference the 'EnvDrift' output channel but the extension never "
            "creates it — register it or fix the docs"
        )

    def test_runtime_deps_are_bundled_into_a_self_contained_artifact(self) -> None:
        """The vsix must ship a self-contained esbuild bundle, not loose modules.

        Regression (#584): the extension gained its first runtime dependency
        (``cross-spawn``), but the vsix carries no ``node_modules``
        (``.vscodeignore`` excludes them; CI packages with
        ``--no-dependencies``). The compiled entrypoint does a runtime
        ``require('cross-spawn')``, so without bundling the packaged extension
        throws ``Cannot find module 'cross-spawn'`` at activation. This pins the
        packaging config that keeps every runtime dep inlined into
        ``dist/extension.js``; the vscode-ci ``package`` job verifies the built
        vsix empirically.
        """
        pkg = json.loads((VSCODE_DIR / "package.json").read_text(encoding="utf-8"))

        # `main` is the esbuild bundle, not the tsc output that ships nothing.
        assert pkg["main"].replace("\\", "/").startswith("./dist/"), pkg["main"]

        # esbuild bundles src/ and externalizes only `vscode` (host-injected).
        assert "esbuild" in pkg.get("devDependencies", {}), "esbuild dev dep missing"
        bundle_script = pkg["scripts"]["bundle"]
        assert "esbuild" in bundle_script and "--bundle" in bundle_script, bundle_script
        assert "--external:vscode" in bundle_script, bundle_script
        assert pkg["scripts"]["vscode:prepublish"] == "npm run bundle", (
            "vsce must run the bundle at package time via vscode:prepublish"
        )

        # The runtime dep that must be inlined is real and imported in source.
        assert "cross-spawn" in pkg.get("dependencies", {}), "cross-spawn runtime dep missing"
        combined_src = "\n".join(p.read_text(encoding="utf-8") for p in _extension_sources())
        assert "from 'cross-spawn'" in combined_src or 'from "cross-spawn"' in combined_src, (
            "cross-spawn is declared but never imported — stale dependency"
        )

        # The vsix ships only the bundle: no node_modules, no tsc `out/` tree.
        ignored = {
            line.strip()
            for line in (VSCODE_DIR / ".vscodeignore").read_text(encoding="utf-8").splitlines()
        }
        assert "node_modules/**" in ignored, ".vscodeignore must exclude node_modules/**"
        assert "out/**" in ignored, ".vscodeignore must exclude the tsc out/ tree"


@pytest.mark.integration
class TestAgentCliContract:
    """The agent argv the extension uses must work on the real Go binary."""

    @pytest.fixture(scope="class")
    def agent_binary(self, tmp_path_factory: pytest.TempPathFactory) -> Path:
        go = shutil.which("go")
        if not go:
            pytest.skip("go toolchain not available")
        binary = tmp_path_factory.mktemp("agent-bin") / (
            "envdrift-agent.exe" if sys.platform == "win32" else "envdrift-agent"
        )
        build = subprocess.run(
            [go, "build", "-o", str(binary), "./cmd/envdrift-agent"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=AGENT_DIR,
            env=os.environ.copy(),
            timeout=300,
        )
        assert build.returncode == 0, build.stderr
        return binary

    def test_extension_agent_argvs_are_real_subcommands(self, agent_binary: Path) -> None:
        result = subprocess.run(
            [str(agent_binary), "--help"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_clean_env(),
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        available = set(
            re.findall(r"^  (\S+)", result.stdout.split("Available Commands:")[1], re.M)
        )
        for command in sorted(_extension_agent_commands()):
            assert command in available, (
                f"extension spawns `envdrift-agent {command}` but the real agent "
                f"only provides: {sorted(available)}"
            )

    def test_agent_version_subcommand_output(self, agent_binary: Path) -> None:
        result = subprocess.run(
            [str(agent_binary), "version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_clean_env(),
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        assert re.match(r"^envdrift-agent \S+", result.stdout), result.stdout

    def test_agent_status_output_matches_extension_parser(
        self, agent_binary: Path, tmp_path: Path
    ) -> None:
        """The real `status` output keeps the line shape the extension parses.

        The mocha suite drives ``parseAgentStatusOutput`` against the fixture
        captures in ``envdrift-vscode/src/test/unit/fixtures``; this test pins
        those fixtures to the real binary's output shape, closing the loop so
        the parser is effectively tested against reality.
        """
        env = _clean_env(HOME=str(tmp_path), USERPROFILE=str(tmp_path))
        result = subprocess.run(
            [str(agent_binary), "status"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        assert re.search(r"^Installed:\s+(true|false)\s*$", result.stdout, re.M), result.stdout
        assert re.search(r"^Running:\s+(true|false)\s*$", result.stdout, re.M), result.stdout

        def labels(text: str) -> list[str]:
            return [line.split(":", 1)[0] for line in text.splitlines() if ":" in line]

        fixtures_dir = VSCODE_SRC / "test" / "unit" / "fixtures"
        for name, expected_running in (
            ("agent-status-stopped.txt", "false"),
            ("agent-status-running.txt", "true"),
        ):
            fixture = (fixtures_dir / name).read_text(encoding="utf-8")
            assert labels(fixture) == labels(result.stdout), (
                f"{name} drifted from the real `envdrift-agent status` output; "
                f"update the fixture so the extension parser is tested against "
                f"reality.\nfixture:\n{fixture}\nreal:\n{result.stdout}"
            )
            match = re.search(r"^Running:\s+(true|false)\s*$", fixture, re.M)
            assert match and match.group(1) == expected_running, fixture


@pytest.mark.integration
class TestEncryptEndToEndContract:
    """The exact per-file spawn the extension performs, on the real stack."""

    def test_extension_argv_encrypts_a_real_file(self, tmp_path: Path) -> None:
        if not shutil.which("dotenvx"):
            pytest.skip("dotenvx binary not available")
        sub = _extension_envdrift_subcommand()
        env_file = tmp_path / ".env.production"
        env_file.write_text("API_KEY=plain_test_value\n", encoding="utf-8")

        # The extension spawns: cwd=dirname(file), argv=[sub, '--', basename(file)].
        result = subprocess.run(
            [*_envdrift_cmd(), sub, "--", ".env.production"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=tmp_path,
            env=_clean_env(),
            timeout=120,
        )
        assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"

        content = env_file.read_text(encoding="utf-8")
        assert "plain_test_value" not in content, "plaintext secret must be gone"
        assert "encrypted:" in content
        assert "DOTENV_PUBLIC_KEY" in content

    def test_dash_prefixed_filename_needs_the_option_terminator(self, tmp_path: Path) -> None:
        """A dash-prefixed filename encrypts only because the extension sends ``--``.

        Regression: without the ``--`` option terminator the Typer CLI parses a
        ``-``-prefixed name as an unknown option and exits non-zero without
        encrypting. The extension's ``encrypt -- <file>`` argv must handle it.
        """
        if not shutil.which("dotenvx"):
            pytest.skip("dotenvx binary not available")
        sub = _extension_envdrift_subcommand()
        env_file = tmp_path / "-weird.env"
        env_file.write_text("API_KEY=plain_test_value\n", encoding="utf-8")

        # Without `--`, Typer rejects the dash-prefixed name as an option.
        without_sep = subprocess.run(
            [*_envdrift_cmd(), sub, "-weird.env"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=tmp_path,
            env=_clean_env(),
            timeout=120,
        )
        assert without_sep.returncode != 0, "a dash-prefixed name must fail without `--`"
        assert "plain_test_value" in env_file.read_text(encoding="utf-8"), "file must be untouched"

        # With `--` (the extension's real argv), the same name encrypts.
        with_sep = subprocess.run(
            [*_envdrift_cmd(), sub, "--", "-weird.env"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=tmp_path,
            env=_clean_env(),
            timeout=120,
        )
        assert with_sep.returncode == 0, f"stdout: {with_sep.stdout}\nstderr: {with_sep.stderr}"
        content = env_file.read_text(encoding="utf-8")
        assert "plain_test_value" not in content, "plaintext secret must be gone"
        assert "encrypted:" in content
