"""SOPS encryption backend implementation.

Mozilla SOPS (Secrets OPerationS) is a tool for encrypting values within files
while keeping the structure visible. It supports various key management systems
including AWS KMS, GCP KMS, Azure Key Vault, age, and PGP.

For .env files, SOPS encrypts the values while keeping the key names visible.
Encrypted values have the format: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # nosec B404
from pathlib import Path
from threading import Lock

from envdrift.encryption.base import (
    EncryptionBackend,
    EncryptionBackendError,
    EncryptionNotFoundError,
    EncryptionResult,
    EncryptionStatus,
)


class SOPSEncryptionBackend(EncryptionBackend):
    """Encryption backend using Mozilla SOPS.

    SOPS encrypts values in-place while preserving file structure.
    It supports multiple key management systems:
    - AWS KMS
    - GCP KMS
    - Azure Key Vault
    - age (modern, simple encryption)
    - PGP

    Configuration is typically stored in .sops.yaml in the project root.
    """

    # Pattern to match SOPS encrypted values
    # Format: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
    ENCRYPTED_PATTERN = re.compile(r"^ENC\[AES256_GCM,")

    # Line-anchored SOPS metadata markers, matched with re.MULTILINE so a bare
    # in-line 'sops:' substring in plaintext (e.g. URL=https://sops:8200) does NOT
    # match, but a genuine SOPS metadata block in any output format does.
    SOPS_METADATA_PATTERNS = [
        re.compile(r"^sops:\s*$", re.MULTILINE),  # YAML: top-level `sops:` mapping (col 0)
        re.compile(r'^\s*"sops"\s*:', re.MULTILINE),  # JSON: `"sops":` (allows indent)
        re.compile(r"^sops_version\s*=", re.MULTILINE),  # dotenv: flat `sops_version=`
        re.compile(r"^sops_mac\s*=", re.MULTILINE),  # dotenv: flat `sops_mac=`
    ]

    def __init__(
        self,
        config_file: Path | str | None = None,
        age_key: str | None = None,
        age_key_file: Path | str | None = None,
        auto_install: bool = False,
    ):
        """
        Initialize the SOPS encryption backend.

        Parameters:
            config_file (Path | str | None): Path to .sops.yaml configuration file.
            age_key (str | None): Age private key for decryption (can also be set via
                                  SOPS_AGE_KEY environment variable).
            age_key_file (Path | str | None): Path to age key file (SOPS_AGE_KEY_FILE).
            auto_install (bool): If True, attempt to auto-install SOPS when missing.
        """
        self._config_file = Path(config_file) if config_file else None
        self._age_key = age_key
        self._age_key_file = Path(age_key_file) if age_key_file else None
        self._auto_install = auto_install
        self._binary_path: Path | None = None
        self._binary_path_lock = Lock()
        self._install_error: str | None = None

    @property
    def name(self) -> str:
        """Return backend name."""
        return "sops"

    @property
    def encrypted_value_prefix(self) -> str:
        """Return the prefix used to identify encrypted values."""
        return "ENC["

    def _find_binary(self) -> Path | None:
        """Find the SOPS binary in PATH."""
        if self._binary_path and self._binary_path.exists():
            return self._binary_path

        with self._binary_path_lock:
            if self._binary_path and self._binary_path.exists():
                return self._binary_path

            try:
                from envdrift.integrations.sops import get_sops_path

                venv_path = get_sops_path()
                if venv_path.exists():
                    self._binary_path = venv_path
                    return self._binary_path
            except RuntimeError:
                pass

            # Check system PATH
            sops_path = shutil.which("sops")
            if sops_path:
                self._binary_path = Path(sops_path)
                return self._binary_path

            if self._auto_install:
                from envdrift.integrations.sops import SopsInstaller, SopsInstallError

                try:
                    installer = SopsInstaller()
                    self._binary_path = installer.install()
                    return self._binary_path
                except SopsInstallError as e:
                    # Record the cause so not-installed errors can surface it
                    # instead of recommending the auto_install that just
                    # failed (#475).
                    self._install_error = str(e)
                    return None

        return None

    def is_installed(self) -> bool:
        """Check if SOPS is installed."""
        return self._find_binary() is not None

    @property
    def install_error(self) -> str | None:
        """Failure reason recorded by the last auto-install attempt, if any."""
        return self._install_error

    def _not_installed_message(self) -> str:
        """Build the not-installed error, surfacing any auto-install failure."""
        if self._install_error:
            return (
                f"SOPS is not installed (auto-install failed: {self._install_error}).\n"
                f"{self.install_instructions()}"
            )
        return f"SOPS is not installed.\n{self.install_instructions()}"

    def get_version(self) -> str | None:
        """Get the installed SOPS version."""
        binary = self._find_binary()
        if not binary:
            return None

        try:
            result = subprocess.run(  # nosec B603
                [str(binary), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                # Output is like "sops 3.8.1 (latest)"
                return result.stdout.strip().split()[1] if result.stdout else None
        except Exception:  # nosec B110
            # Intentionally return None for any error during version check
            return None
        return None

    def _build_env(self, env: dict[str, str] | None = None) -> dict[str, str]:
        """Build environment dict with SOPS-specific variables.

        Precedence (most specific wins): a per-call ``env`` dict, then explicit
        backend config (CLI ``--age-key-file``/``--age-key`` or TOML
        ``age_key_file``/``age_key``), then the ambient process environment. An
        ambient ``SOPS_AGE_KEY_FILE``/``SOPS_AGE_KEY`` export must NOT silently
        override an explicitly supplied key (#475) — the documented setup exports
        the env var, which previously made the explicit flag dead.
        """
        result = dict(os.environ)

        # Explicit config outranks the ambient environment.
        if self._age_key:
            result["SOPS_AGE_KEY"] = self._age_key
        if self._age_key_file:
            result["SOPS_AGE_KEY_FILE"] = str(self._age_key_file)

        # A per-call env dict is the most specific request of all.
        if env:
            result.update(env)

        return result

    def _resolve_config_path(self, cwd: Path | str | None) -> Path | None:
        """Resolve the explicit SOPS config path against the subprocess ``cwd``.

        ``self._config_file`` is only ever set from an explicit CLI
        ``--sops-config`` or TOML ``sops_config_file`` (never auto-discovery), so a
        missing one is always an explicit-but-wrong path. A *relative* config path
        is resolved against the ``cwd`` SOPS will run in (not the process cwd), so
        validation matches how SOPS itself would locate it.

        The result is always made absolute: SOPS runs with ``cwd`` as its working
        directory, so passing a still-relative ``--config`` would make SOPS resolve
        it against ``cwd`` a *second* time. Anchoring to an absolute path here
        (including when ``cwd`` itself is relative) avoids that double application.
        """
        if self._config_file is None:
            return None
        config_path = self._config_file
        if config_path.is_absolute():
            return config_path
        if cwd is not None:
            # Anchor a relative config under cwd, then make absolute so SOPS does
            # not re-resolve it against its own working directory.
            return (Path(cwd) / config_path).resolve()
        return config_path

    def _config_args(self, cwd: Path | str | None) -> list[str]:
        """Build the ``--config <path>`` args, validating an explicit config path.

        Raises ``EncryptionBackendError`` when an explicit config path does not
        exist: silently dropping ``--config`` would let SOPS fall back to an
        ambient ``.sops.yaml`` (wrong keys, exit 0 — a data-integrity hazard)
        instead of surfacing the typo. Returns an empty list when no config is set.
        """
        config_path = self._resolve_config_path(cwd)
        if config_path is None:
            return []
        if not config_path.exists():
            raise EncryptionBackendError(f"SOPS config file not found: {config_path}")
        # SOPS treats flags after positional args as extra paths, so --config must
        # precede them; callers prepend this list before the positional file.
        return ["--config", str(config_path)]

    def _run(
        self,
        args: list[str],
        env: dict[str, str] | None = None,
        cwd: Path | str | None = None,
    ) -> subprocess.CompletedProcess:
        """Run SOPS command."""
        binary = self._find_binary()
        if not binary:
            raise EncryptionNotFoundError(self._not_installed_message())

        cmd = [str(binary), *self._config_args(cwd), *args]

        try:
            result = subprocess.run(  # nosec B603
                cmd,
                capture_output=True,
                text=True,
                # SOPS emits UTF-8; decode it as such rather than the platform
                # locale (cp1252 on Windows would corrupt non-ASCII secret values
                # or raise UnicodeDecodeError).
                encoding="utf-8",
                errors="replace",
                timeout=120,
                env=self._build_env(env),
                cwd=str(cwd) if cwd else None,
            )
            return result
        except subprocess.TimeoutExpired as e:
            raise EncryptionBackendError("SOPS command timed out") from e
        except FileNotFoundError as e:
            raise EncryptionNotFoundError(f"SOPS binary not found: {e}") from e

    def encrypt(
        self,
        env_file: Path | str,
        keys_file: Path | str | None = None,
        **kwargs,
    ) -> EncryptionResult:
        """
        Encrypt a .env file using SOPS.

        Parameters:
            env_file (Path | str): Path to the .env file to encrypt.
            keys_file (Path | str | None): Not used for SOPS (keys come from .sops.yaml
                                           or environment).
            **kwargs: Additional options:
                - env (dict): Environment variables to pass to subprocess.
                - cwd (Path | str): Working directory for subprocess.
                - in_place (bool): Encrypt in-place (default True).
                - output_file (Path | str): Write ciphertext to a different file
                  (required when in_place is False).
                - age_recipients (str): Age public keys for encryption.
                - kms_arn (str): AWS KMS key ARN.
                - gcp_kms (str): GCP KMS resource ID.
                - azure_kv (str): Azure Key Vault key URL.

        Returns:
            EncryptionResult: Result of the encryption operation.
        """
        env_file = Path(env_file)

        if not env_file.exists():
            return EncryptionResult(
                success=False,
                message=f"File not found: {env_file}",
                file_path=env_file,
            )

        if not self.is_installed():
            raise EncryptionNotFoundError(self._not_installed_message())

        # Validate an explicit config path up front, *before* the idempotency
        # short-circuit, so a misconfigured --sops-config is always surfaced — even
        # when the target is already encrypted and _run() would otherwise be skipped.
        self._config_args(kwargs.get("cwd"))

        noop = self._already_encrypted_noop(env_file, kwargs)
        if noop is not None:
            return noop

        output_file = kwargs.get("output_file")
        output_args = self._encrypt_output_args(env_file, kwargs)
        if isinstance(output_args, EncryptionResult):
            return output_args

        args = [
            "--encrypt",
            *self._encrypt_key_args(kwargs),
            *output_args,
            "--input-type",
            "dotenv",
            "--output-type",
            "dotenv",
            str(env_file),
        ]

        result = self._run(args, env=kwargs.get("env"), cwd=kwargs.get("cwd"))

        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            raise EncryptionBackendError(f"SOPS encryption failed: {error_msg}")

        output_path = Path(output_file) if output_file else env_file
        return EncryptionResult(
            success=True,
            message=f"Encrypted {output_path}",
            file_path=output_path,
        )

    def _already_encrypted_noop(self, env_file: Path, kwargs: dict) -> EncryptionResult | None:
        """Idempotency short-circuit for an already-encrypted in-place target.

        SOPS refuses to re-encrypt a file that already carries a ``sops`` metadata
        block and exits non-zero, which would surface as an EncryptionBackendError
        -> exit 1 on any second run (a pre-commit hook firing twice, a CI re-run, a
        documented re-run). Mirror the dotenvx path and treat such an in-place
        target as a clean no-op. Returns ``None`` when encryption should proceed.

        Skipped for an explicit ``output_file`` (a distinct target that must still
        be written). Detection uses the genuine line-anchored SOPS metadata block
        (not a bare ``ENC[AES256_GCM,`` substring, which can appear in plaintext),
        matching exactly what SOPS refuses to re-encrypt.

        Metadata presence alone is NOT proof the post-condition holds (#475):
        before declaring a no-op, verify that no plaintext value survives in the
        file and that every explicitly requested recipient is already present in
        the metadata. Either violation is a loud failure — sops itself refuses
        such a file (exit 203), so "[OK] Encrypted" here would be a false success
        (a plaintext leak, or a teammate who silently never got access).
        """
        if kwargs.get("output_file"):
            return None
        try:
            existing = env_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        if not existing or not self._has_sops_metadata_block(existing):
            return None

        plaintext_keys = self._plaintext_keys(existing)
        if plaintext_keys:
            keys = ", ".join(sorted(plaintext_keys))
            return EncryptionResult(
                success=False,
                message=(
                    f"{env_file} carries SOPS metadata but still contains plaintext "
                    f"value(s): {keys}. sops refuses to re-encrypt a file with existing "
                    f"metadata, so these values are NOT protected. Recover with "
                    f"`sops edit {env_file}`, or move the plaintext line(s) aside, run "
                    f"`envdrift decrypt {env_file}`, re-add them, then re-run "
                    f"`envdrift encrypt {env_file}`."
                ),
                file_path=env_file,
            )

        missing = self._missing_requested_recipients(existing, kwargs)
        if missing:
            recipients = ", ".join(missing)
            return EncryptionResult(
                success=False,
                message=(
                    f"{env_file} is already encrypted, but its SOPS metadata does not "
                    f"include the requested recipient(s): {recipients}. Re-running "
                    f"encrypt cannot add recipients; use `sops rotate --add-age "
                    f"<recipient> -i --input-type dotenv --output-type dotenv "
                    f"{env_file}` (or `sops updatekeys` with an updated .sops.yaml), "
                    f"or decrypt and re-encrypt."
                ),
                file_path=env_file,
            )

        return EncryptionResult(
            success=True,
            message=f"{env_file} is already encrypted (no change)",
            file_path=env_file,
            changed=False,
        )

    # Metadata keys that mark selective-encryption rules: plaintext values are
    # then intentional and the surviving-plaintext check cannot infer intent.
    _SELECTIVE_ENCRYPTION_METADATA = re.compile(
        r"^sops_(encrypted_suffix|encrypted_regex|unencrypted_regex)\s*=", re.MULTILINE
    )
    _UNENCRYPTED_SUFFIX_METADATA = re.compile(r"^sops_unencrypted_suffix\s*=(.*)$", re.MULTILINE)

    def has_plaintext_values(self, content: str) -> bool:
        """Return True iff dotenv ``content`` carries surviving plaintext values.

        For callers that must not equate "has a SOPS metadata block" with "fully
        encrypted" (#475): a value appended after encryption stays plaintext
        while the block still matches. Honors the file's own metadata (see
        :meth:`_plaintext_keys`), unlike the coarser line scan in
        ``core.partial_encryption.has_plaintext_secret_value``.
        """
        return bool(self._plaintext_keys(content))

    def _plaintext_keys(self, content: str) -> list[str]:
        """List keys carrying plaintext values in SOPS dotenv ``content``.

        Honors the file's own metadata: keys with the recorded
        ``sops_unencrypted_suffix`` (default ``_unencrypted``) are intentionally
        plaintext, and files using selective-encryption rules
        (``encrypted_suffix`` / ``encrypted_regex`` / ``unencrypted_regex``) are
        skipped entirely because plaintext is then by design. Empty values are
        not plaintext (sops keeps them empty).

        Metadata is excluded via the canonical exact-family matcher
        (``_is_sops_metadata_key``, applied inside ``_line_has_plaintext_secret``),
        NOT a bare ``sops_`` prefix: a prefix match would also skip a real user
        secret merely named ``sops_token=…`` / ``sops_api_key=…``, silently
        blessing a plaintext leak (#416, #475).

        Scans line-by-line rather than the parser's deduplicated variables dict:
        with duplicate keys the dict keeps only the last assignment, so a later
        encrypted duplicate would hide an earlier surviving plaintext line and
        the leak would be blessed as "already encrypted".
        """
        if self._SELECTIVE_ENCRYPTION_METADATA.search(content):
            return []
        suffix_match = self._UNENCRYPTED_SUFFIX_METADATA.search(content)
        unencrypted_suffix = suffix_match.group(1).strip() if suffix_match else "_unencrypted"

        from envdrift.core.partial_encryption import _line_has_plaintext_secret

        plaintext: list[str] = []
        for raw_line in content.splitlines():
            if not _line_has_plaintext_secret(raw_line):
                continue
            name = raw_line.strip().partition("=")[0].strip()
            if unencrypted_suffix and name.endswith(unencrypted_suffix):
                continue
            if name not in plaintext:
                plaintext.append(name)
        return plaintext

    @staticmethod
    def _requested_recipients(kwargs: dict) -> list[str]:
        """Flatten the explicitly requested recipient values from encrypt() kwargs."""
        requested: list[str] = []
        for key in ("age_recipients", "kms_arn", "gcp_kms", "azure_kv"):
            value = kwargs.get(key)
            if value:
                requested.extend(part.strip() for part in str(value).split(",") if part.strip())
        return requested

    def _missing_requested_recipients(self, content: str, kwargs: dict) -> list[str]:
        """Requested recipients absent from the file's SOPS metadata."""
        return [
            recipient
            for recipient in self._requested_recipients(kwargs)
            if not self._recipient_in_metadata(content, recipient)
        ]

    def missing_recipients(self, content: str, **kwargs) -> list[str]:
        """Explicitly requested recipients absent from ``content``'s SOPS metadata.

        Public entry point for callers like ``lock`` that skip ``encrypt()`` for
        an already-encrypted file but must still verify that every configured
        recipient (``age_recipients``/``kms_arn``/``gcp_kms``/``azure_kv``) is
        recorded in the metadata — otherwise "skipped (already encrypted)" would
        silently ignore a recipient newly added to envdrift.toml (#475).
        """
        return self._missing_requested_recipients(content, kwargs)

    @staticmethod
    def _metadata_line_has_value(content: str, value: str) -> bool:
        """Exact match of ``value`` against a SOPS *key-group* metadata entry.

        Only the recipient-carrying key-group family counts (``sops_age__*`` /
        ``sops_pgp__*`` / ``sops_kms__*`` / ``sops_gcp_kms__*`` /
        ``sops_azure_kv__*`` / ``sops_hc_vault__*``, via the canonical
        ``_SOPS_METADATA_GROUP_KEY``):
        recipients are never recorded in scalar bookkeeping, so an unrelated
        scalar value (``sops_shamir_threshold=1``) must not satisfy a short
        component like an Azure key version ``1``. Whole-line equality kills the
        substring false-positive classes of #475: a requested recipient that is
        a prefix of a longer recorded key never matches, and neither do digits
        inside ``sops_version=3.13.2``.
        """
        from envdrift.core.partial_encryption import _SOPS_METADATA_GROUP_KEY

        for raw_line in content.splitlines():
            key, sep, raw_value = raw_line.partition("=")
            if not sep or not _SOPS_METADATA_GROUP_KEY.match(key.strip()):
                continue
            if raw_value.strip() == value:
                return True
        return False

    # One azure_kv metadata record per recipient key. sops' dotenv store
    # flattens each record to ``sops_azure_kv__list_N__map_<field>=...``
    # (verified against the real binary; two recipients render as list_0 and
    # list_1); the flat ``sops_azure_kv_<field>`` single-record form is
    # accepted defensively.
    _AZURE_KV_RECORD_KEY = re.compile(
        r"^sops_azure_kv(?:__list_(?P<idx>\d+)__map_|_)(?P<field>\w+)$"
    )

    @staticmethod
    def _azure_kv_records(content: str) -> list[dict[str, str]]:
        """Parse the azure_kv metadata records (one dict per recipient key)."""
        records: dict[str, dict[str, str]] = {}
        for raw_line in content.splitlines():
            key, sep, raw_value = raw_line.partition("=")
            if not sep:
                continue
            match = SOPSEncryptionBackend._AZURE_KV_RECORD_KEY.match(key.strip())
            if not match:
                continue
            idx = match.group("idx") if match.group("idx") is not None else "flat"
            records.setdefault(idx, {})[match.group("field")] = raw_value.strip()
        return list(records.values())

    @staticmethod
    def _recipient_in_metadata(content: str, recipient: str) -> bool:
        """Check whether ``recipient`` is recorded in the file's SOPS metadata.

        age keys, KMS ARNs and GCP resource IDs are stored verbatim as one flat
        dotenv metadata value, so an exact line-anchored match is authoritative.
        Azure Key Vault URLs are stored split across ``vault_url``/``name``/
        ``version`` fields of ONE record per recipient, so the URL is decomposed
        and every component must match its own field within a SINGLE record —
        matching components across different records (vault host from any, key
        name from record 0, version from record 1) would declare a
        never-registered key "present" on any file encrypted to two keys of the
        same vault.
        """
        if SOPSEncryptionBackend._metadata_line_has_value(content, recipient):
            return True
        if "/keys/" in recipient:
            base, _, rest = recipient.partition("/keys/")
            parts = [part for part in rest.split("/") if part]
            if not parts or len(parts) > 2:
                return False
            name = parts[0]
            version = parts[1] if len(parts) == 2 else None
            return any(
                record.get("vault_url") == base
                and record.get("name") == name
                and (version is None or record.get("version") == version)
                for record in SOPSEncryptionBackend._azure_kv_records(content)
            )
        return False

    @staticmethod
    def _encrypt_key_args(kwargs: dict) -> list[str]:
        """Build the SOPS recipient/key flags from encrypt() kwargs."""
        flag_for_kwarg = {
            "age_recipients": "--age",
            "kms_arn": "--kms",
            "gcp_kms": "--gcp-kms",
            "azure_kv": "--azure-kv",
        }
        args: list[str] = []
        for key, flag in flag_for_kwarg.items():
            value = kwargs.get(key)
            if value:
                args.extend([flag, value])
        return args

    def _encrypt_output_args(self, env_file: Path, kwargs: dict) -> list[str] | EncryptionResult:
        """Resolve the output destination flags for encrypt().

        Returns the args list on success, or an ``EncryptionResult`` failure when
        neither in-place nor an output file is requested (otherwise sops would
        stream the ciphertext to discarded stdout, leaving the file PLAINTEXT while
        reporting success).
        """
        output_file = kwargs.get("output_file")
        if output_file:
            return ["--output", str(output_file)]
        if kwargs.get("in_place", True):
            return ["--in-place"]
        return EncryptionResult(
            success=False,
            message=(
                "encrypt(in_place=False) requires an output_file; "
                "otherwise the ciphertext is discarded and the file stays plaintext."
            ),
            file_path=env_file,
        )

    def decrypt(
        self,
        env_file: Path | str,
        keys_file: Path | str | None = None,
        **kwargs,
    ) -> EncryptionResult:
        """
        Decrypt a .env file using SOPS.

        Parameters:
            env_file (Path | str): Path to the .env file to decrypt.
            keys_file (Path | str | None): Not used for SOPS.
            **kwargs: Additional options:
                - env (dict): Environment variables to pass to subprocess.
                - cwd (Path | str): Working directory for subprocess.
                - in_place (bool): Decrypt in-place (default True).
                - output_file (Path | str): Write output to different file.

        Returns:
            EncryptionResult: Result of the decryption operation.
        """
        env_file = Path(env_file)

        if not env_file.exists():
            return EncryptionResult(
                success=False,
                message=f"File not found: {env_file}",
                file_path=env_file,
            )

        if not self.is_installed():
            raise EncryptionNotFoundError(self._not_installed_message())

        # Build SOPS arguments
        args = ["--decrypt"]

        # In-place decryption by default
        in_place = kwargs.get("in_place", True)
        output_file = kwargs.get("output_file")

        if output_file:
            args.extend(["--output", str(output_file)])
        elif in_place:
            args.append("--in-place")
        else:
            # Neither in-place nor an output file: sops would stream plaintext to
            # stdout where _run() captures and discards it. Refuse rather than
            # silently dropping the decrypted secrets while reporting success.
            return EncryptionResult(
                success=False,
                message=(
                    "decrypt(in_place=False) requires an output_file; "
                    "otherwise the decrypted plaintext is discarded."
                ),
                file_path=env_file,
            )

        # Specify input type for .env files
        args.extend(["--input-type", "dotenv", "--output-type", "dotenv"])

        args.append(str(env_file))

        result = self._run(
            args,
            env=kwargs.get("env"),
            cwd=kwargs.get("cwd"),
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            raise EncryptionBackendError(f"SOPS decryption failed: {error_msg}")

        output_path = Path(output_file) if output_file else env_file
        return EncryptionResult(
            success=True,
            message=f"Decrypted {output_path}",
            file_path=output_path,
        )

    def detect_encryption_status(self, value: str) -> EncryptionStatus:
        """
        Detect the encryption status of a value.

        Parameters:
            value (str): The unquoted value string to classify.

        Returns:
            EncryptionStatus: EMPTY if value is empty, ENCRYPTED if it matches
                              SOPS encrypted pattern (ENC[...), PLAINTEXT otherwise.
        """
        if not value:
            return EncryptionStatus.EMPTY

        if self.ENCRYPTED_PATTERN.match(value):
            return EncryptionStatus.ENCRYPTED

        return EncryptionStatus.PLAINTEXT

    def has_encrypted_header(self, content: str) -> bool:
        """
        Check if file content contains SOPS encryption markers.

        Parameters:
            content (str): Raw file content to inspect.

        Returns:
            bool: True if SOPS encryption markers are present.
        """
        # Check for ENC[] encrypted values anywhere in content
        # The pattern is re-created without anchoring to search anywhere
        if "ENC[AES256_GCM," in content:
            return True

        return self._has_sops_metadata_block(content)

    def has_metadata_block(self, content: str) -> bool:
        """Public alias of :meth:`_has_sops_metadata_block` for CLI-layer checks.

        Callers deciding whether a file is genuinely SOPS-managed (``lock``'s
        post-state check, ``pull``'s decrypt gate) must key off the metadata
        block — a bare ``ENC[AES256_GCM,`` token can appear verbatim in a
        plaintext value or comment, and a file without the metadata block is not
        decryptable by sops anyway.
        """
        return self._has_sops_metadata_block(content)

    def _has_sops_metadata_block(self, content: str) -> bool:
        """Return True iff ``content`` carries a genuine SOPS *metadata block*.

        This is stricter than :meth:`has_encrypted_header`: it ignores bare
        ``ENC[AES256_GCM,`` substrings (which can appear verbatim in a plaintext
        comment or value) and looks only for the line-anchored metadata block SOPS
        itself writes (``sops:`` / ``"sops":`` / ``sops_version=`` / ``sops_mac=``).
        SOPS refuses to re-encrypt a file with such a block, so this is the precise
        signal for the idempotency short-circuit.
        """
        return any(pattern.search(content) for pattern in self.SOPS_METADATA_PATTERNS)

    def install_instructions(self) -> str:
        """Return installation instructions for SOPS."""
        from envdrift.integrations.sops import SOPS_VERSION

        # No "SOPS is not installed." lead-in here: every caller
        # (_not_installed_message, the CLI's _report_not_installed) prints its
        # own lead sentence, so repeating it made the message say "not
        # installed" twice in consecutive lines.
        return f"""
Installation options:

macOS (Homebrew):
  brew install sops

Linux (apt):
  # Download latest release from https://github.com/getsops/sops/releases
  wget https://github.com/getsops/sops/releases/download/v{SOPS_VERSION}/sops-v{SOPS_VERSION}.linux.amd64
  chmod +x sops-v{SOPS_VERSION}.linux.amd64
  sudo mv sops-v{SOPS_VERSION}.linux.amd64 /usr/local/bin/sops

Windows (Chocolatey):
  choco install sops

Optional auto-install:
  Set [encryption.sops] auto_install = true in envdrift.toml

After installing SOPS, you'll also need to set up encryption keys.
Common options:
  - age: Simple, modern encryption (recommended for local dev)
    Install: brew install age  # or download from https://github.com/FiloSottile/age
    Generate key: age-keygen -o key.txt
    Set env: export SOPS_AGE_KEY_FILE=key.txt

  - AWS KMS: For AWS-based workflows
  - GCP KMS: For Google Cloud workflows
  - Azure Key Vault: For Azure workflows

See https://github.com/getsops/sops for full documentation.
"""

    def exec_env(
        self,
        env_file: Path | str,
        command: list[str],
        **kwargs,
    ) -> subprocess.CompletedProcess:
        """
        Execute a command with decrypted environment variables.

        SOPS supports running commands with decrypted secrets injected
        as environment variables without writing them to disk.

        Parameters:
            env_file (Path | str): Path to the encrypted .env file.
            command (list[str]): Command and arguments to execute.
            **kwargs: Additional options:
                - env (dict): Additional environment variables.
                - cwd (Path | str): Working directory.

        Returns:
            subprocess.CompletedProcess: Result of the command execution.
        """
        env_file = Path(env_file)

        if not env_file.exists():
            raise EncryptionBackendError(f"File not found: {env_file}")

        if not self.is_installed():
            raise EncryptionNotFoundError(self._not_installed_message())

        # Decrypt to memory and run the command directly as argv, rather than via
        # `sops exec-env`. sops' exec-env runs the command through a shell, which
        # makes quoting platform-specific and brittle (on Windows, cmd.exe mangles
        # a ``python -c "...'...'..."`` string). Decrypting to stdout and invoking
        # the child with subprocess (no shell) injects the same secrets without
        # ever writing plaintext to disk, and behaves identically on every OS.
        decrypt = self._run(
            ["-d", "--input-type", "dotenv", "--output-type", "dotenv", str(env_file)],
            env=kwargs.get("env"),
            cwd=kwargs.get("cwd"),
        )
        if decrypt.returncode != 0:
            raise EncryptionBackendError(f"sops decryption failed: {decrypt.stderr.strip()}")

        from envdrift.core.parser import EnvParser

        secrets = {
            name: var.value
            for name, var in EnvParser().parse_string(decrypt.stdout).variables.items()
        }
        child_env = dict(os.environ)
        if kwargs.get("env"):
            child_env.update(kwargs["env"])
        child_env.update(secrets)

        # Bound the child so a hung process can't block forever (the previous
        # sops-exec-env path had _run's 120s timeout; keep a generous default,
        # overridable via the ``timeout`` kwarg).
        try:
            return subprocess.run(  # nosec B603
                command,
                env=child_env,
                cwd=str(kwargs["cwd"]) if kwargs.get("cwd") else None,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=kwargs.get("timeout", 300),
            )
        except subprocess.TimeoutExpired as e:
            raise EncryptionBackendError(f"exec-env command timed out: {e}") from e
