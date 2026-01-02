"""Integration tests for dotenvx and SOPS encryption flows."""

from __future__ import annotations

import os
import subprocess  # nosec B404
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHONPATH = str(REPO_ROOT / "src")

AGE_PUBLIC_KEY = "age1c89jtrvyl72y0muvdp5lm3jpemvc2gr303up4g37tuq4uftcku3q4svqau"
AGE_PRIVATE_KEY = "AGE-SECRET-KEY-1HGE3ZE9NPEN5R76LVKKJ2Z3G9TYZJLW84P2CHAF6UGL43R7TWPUSZ89MK6"


def _run_envdrift(args: list[str], *, cwd: Path, env: dict[str, str], check: bool = True):
    cmd = [sys.executable, "-m", "envdrift.cli", *args]
    result = subprocess.run(  # nosec B603
        cmd,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            "envdrift failed\n"
            f"cmd: {' '.join(cmd)}\n"
            f"cwd: {cwd}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


@pytest.fixture(scope="session")
def integration_env(tmp_path_factory):
    base_dir = tmp_path_factory.mktemp("envdrift-integration")
    venv_dir = base_dir / ".venv"
    bin_dir = venv_dir / ("Scripts" if os.name == "nt" else "bin")
    bin_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["VIRTUAL_ENV"] = str(venv_dir)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env["PYTHONPATH"] = f"{PYTHONPATH}{os.pathsep}{env.get('PYTHONPATH', '')}"

    return {"base_dir": base_dir, "env": env}


@pytest.mark.integration
def test_dotenvx_encrypt_decrypt_roundtrip(integration_env):
    work_dir = integration_env["base_dir"] / "dotenvx"
    work_dir.mkdir()
    env = integration_env["env"].copy()

    env_file = work_dir / ".env.dotenvx"
    env_file.write_text(
        textwrap.dedent(
            """\
            API_URL=https://example.com
            API_KEY=supersecret
            DEBUG=true
            PORT=3000
            """
        )
    )

    config = textwrap.dedent(
        """\
        [encryption]
        backend = "dotenvx"

        [encryption.dotenvx]
        auto_install = true
        """
    )
    (work_dir / "envdrift.toml").write_text(config)

    result = _run_envdrift(
        ["encrypt", env_file.name, "--check"],
        cwd=work_dir,
        env=env,
        check=False,
    )
    assert result.returncode == 1

    _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)
    encrypted = env_file.read_text()
    assert "encrypted:" in encrypted
    assert "DOTENV_PUBLIC_KEY" in encrypted

    _run_envdrift(["decrypt", env_file.name], cwd=work_dir, env=env)
    decrypted = env_file.read_text()
    assert "API_KEY=supersecret" in decrypted
    assert "encrypted:" not in decrypted


@pytest.mark.integration
def test_sops_encrypt_decrypt_roundtrip(integration_env):
    work_dir = integration_env["base_dir"] / "sops"
    work_dir.mkdir()
    env = integration_env["env"].copy()

    env_file = work_dir / ".env.sops"
    env_file.write_text(
        textwrap.dedent(
            """\
            DB_USER=admin
            DB_PASSWORD=hunter2
            """
        )
    )

    (work_dir / "age.key").write_text(
        textwrap.dedent(
            f"""\
            # created: 2026-01-01T23:59:46-05:00
            # public key: {AGE_PUBLIC_KEY}
            {AGE_PRIVATE_KEY}
            """
        )
    )

    (work_dir / ".sops.yaml").write_text(
        textwrap.dedent(
            f"""\
            creation_rules:
              - path_regex: \\.env\\.sops$
                age: {AGE_PUBLIC_KEY}
            """
        )
    )

    config = textwrap.dedent(
        f"""\
        [encryption]
        backend = "sops"

        [encryption.sops]
        auto_install = true
        config_file = ".sops.yaml"
        age_key_file = "age.key"
        age_recipients = "{AGE_PUBLIC_KEY}"
        """
    )
    (work_dir / "envdrift.toml").write_text(config)

    _run_envdrift(["encrypt", env_file.name, "--backend", "sops"], cwd=work_dir, env=env)
    encrypted = env_file.read_text()
    assert "ENC[" in encrypted

    check_result = _run_envdrift(
        ["encrypt", env_file.name, "--backend", "sops", "--check"],
        cwd=work_dir,
        env=env,
        check=False,
    )
    assert check_result.returncode == 0

    _run_envdrift(["decrypt", env_file.name], cwd=work_dir, env=env)
    decrypted = env_file.read_text()
    assert "DB_PASSWORD=hunter2" in decrypted
    assert "ENC[" not in decrypted
