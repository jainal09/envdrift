"""Regression tests for the Infisical CLI repository migration.

The Infisical CLI moved out of the ``Infisical/infisical`` monorepo into
``Infisical/cli``, which changed the release tag format, the release asset
prefix AND split the published checksums by platform. These tests pin the
behaviours that broke (or would have broken silently) during that move.

Split out of ``test_infisical.py`` to keep both modules under the 600-line
code-health threshold.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner.infisical import (
    InfisicalInstaller,
    _get_infisical_download_urls,
    _get_infisical_version,
)


class TestPlatformSpecificChecksums:
    """Regression: macOS digests live in a separate upstream checksums file.

    Upstream Infisical/cli publishes darwin SHA256s in ``checksums-darwin.txt``;
    the generic ``checksums.txt`` contains ZERO darwin entries. Because
    ``verify_download`` fails closed, resolving the generic file on macOS made
    every install abort with a "no checksum entry" error.

    Nothing caught this: CI installs the Linux tarball only, so a broken macOS
    install would have shipped silently.

    Versions are read dynamically from constants.json — never hardcode them
    here, or Renovate bumps break CI.
    """

    @staticmethod
    def _url_for(system: str, machine: str) -> str:
        with patch(
            "envdrift.scanner.infisical.get_platform_info",
            return_value=(system, machine),
        ):
            return InfisicalInstaller().get_checksums_url()

    @pytest.mark.parametrize("machine", ["x86_64", "arm64"])
    def test_darwin_resolves_the_darwin_checksums_file(self, machine: str):
        """On macOS the installer must not use the generic checksums file."""
        url = self._url_for("Darwin", machine)
        assert url.endswith("checksums-darwin.txt"), url
        assert _get_infisical_version() in url

    @pytest.mark.parametrize(
        ("system", "machine"),
        [("Linux", "x86_64"), ("Linux", "arm64"), ("Windows", "x86_64")],
    )
    def test_non_darwin_resolves_the_generic_checksums_file(self, system: str, machine: str):
        """Linux/Windows digests are still published in checksums.txt."""
        url = self._url_for(system, machine)
        assert url.endswith("checksums.txt"), url
        assert "checksums-darwin.txt" not in url
        assert _get_infisical_version() in url

    def test_darwin_and_linux_disagree(self):
        """The whole point: the two platforms must not share one URL."""
        assert self._url_for("Darwin", "arm64") != self._url_for("Linux", "x86_64")

    def test_falls_back_to_generic_when_no_override_configured(self):
        """If upstream re-consolidates, an empty override map degrades gracefully."""
        with (
            patch(
                "envdrift.scanner.infisical._get_infisical_checksums_urls",
                return_value={},
            ),
            patch(
                "envdrift.scanner.infisical.get_platform_info",
                return_value=("Darwin", "arm64"),
            ),
        ):
            assert InfisicalInstaller().get_checksums_url().endswith("checksums.txt")


class TestInstalledVersionMatchIsExact:
    """Regression: the installed-version check was a substring test.

    ``if self.version in result.stdout`` treats a pinned 0.43.11 as satisfied
    by a binary reporting 0.43.116, so a wrong binary is silently kept in
    place. Upstream patch numbers are three digits, so this is reachable.
    """

    @staticmethod
    def _install_with_reported_version(tmp_path: Path, pinned: str, reported: str):
        target = tmp_path / "infisical"
        target.write_text("#!/bin/sh\n")
        installer = InfisicalInstaller(version=pinned)
        with (
            patch("envdrift.scanner.infisical.get_infisical_path", return_value=target),
            patch("envdrift.scanner.infisical.subprocess.run") as run,
            patch.object(InfisicalInstaller, "download_and_extract") as download,
        ):
            run.return_value = MagicMock(
                returncode=0, stdout=f"infisical version {reported}\n", stderr=""
            )
            installer.install()
            return download

    def test_prefix_version_does_not_satisfy_the_pin(self, tmp_path: Path):
        """0.43.116 installed must NOT satisfy a 0.43.11 pin -> reinstall."""
        download = self._install_with_reported_version(tmp_path, "0.43.11", "0.43.116")
        download.assert_called_once()

    def test_exact_version_skips_reinstall(self, tmp_path: Path):
        """The matching version is still recognised -> no redundant download."""
        download = self._install_with_reported_version(tmp_path, "0.43.116", "0.43.116")
        download.assert_not_called()


class TestVersionTokenParsing:
    """Regression: the installed-version check must not accept near-misses.

    Two ways a wrong binary could be mistaken for the pinned one:

    * a substring match, so ``0.43.11`` was satisfied by ``0.43.116`` (upstream
      patch numbers are three digits, so this is reachable);
    * a prerelease build, where ``0.43.116-rc.1`` yields a bare ``0.43.116``.

    And a ``--version`` invocation that FAILED must never mark the binary
    installed, whatever landed on stdout.
    """

    @staticmethod
    def _install(tmp_path: Path, pinned: str, reported: str, returncode: int = 0):
        target = tmp_path / "infisical"
        target.write_text("#!/bin/sh\n")
        installer = InfisicalInstaller(version=pinned)
        with (
            patch("envdrift.scanner.infisical.get_infisical_path", return_value=target),
            patch("envdrift.scanner.infisical.subprocess.run") as run,
            patch.object(InfisicalInstaller, "download_and_extract") as download,
        ):
            run.return_value = MagicMock(returncode=returncode, stdout=reported, stderr="")
            installer.install()
            return download

    def test_prerelease_does_not_satisfy_the_release_pin(self, tmp_path: Path):
        """0.43.116-rc.1 installed must NOT satisfy a 0.43.116 pin."""
        download = self._install(tmp_path, "0.43.116", "infisical version 0.43.116-rc.1\n")
        download.assert_called_once()

    def test_failed_version_command_forces_reinstall(self, tmp_path: Path):
        """A non-zero exit means unusable, even if stdout contains the version."""
        download = self._install(tmp_path, "0.43.116", "infisical version 0.43.116\n", returncode=1)
        download.assert_called_once()

    def test_matching_version_and_clean_exit_skips_reinstall(self, tmp_path: Path):
        """The happy path still avoids a redundant download."""
        download = self._install(tmp_path, "0.43.116", "infisical version 0.43.116\n")
        download.assert_not_called()


def test_constants_cover_every_supported_platform():
    """Every platform the installer claims to support must have a URL.

    ``get_download_url`` now fails loudly on a missing key, which is right, but
    nothing would have caught a hole BEFORE it shipped: the real-constants
    tests only resolve darwin_arm64, linux_amd64 and windows_amd64, so a
    dropped or typoed ``darwin_amd64`` (Intel macs) or ``linux_arm64`` would
    stay green until a user's machine hit the raise.
    """
    configured = set(_get_infisical_download_urls())
    required = {
        f"{os_name}_{arch}" for (os_name, arch, _ext) in InfisicalInstaller.PLATFORM_MAP.values()
    }
    missing = sorted(required - configured)
    assert not missing, (
        f"constants.json infisical_download_urls is missing {missing}. "
        f"PLATFORM_MAP advertises support for these, so install() would raise "
        f"on those machines. Configured: {sorted(configured)}."
    )
