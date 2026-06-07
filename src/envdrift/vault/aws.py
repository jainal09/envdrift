"""AWS Secrets Manager client implementation."""

from __future__ import annotations

import json
from typing import Any

from envdrift.vault.base import (
    AuthenticationError,
    SecretNotFoundError,
    SecretValue,
    VaultClient,
    VaultError,
)

try:
    import boto3 as _boto3
    from botocore.exceptions import (
        BotoCoreError,
        NoCredentialsError,
        PartialCredentialsError,
    )

    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False
    _boto3 = None
    NoCredentialsError = Exception  # type: ignore[misc, assignment]
    PartialCredentialsError = Exception  # type: ignore[misc, assignment]
    BotoCoreError = Exception  # type: ignore[misc, assignment]


def _get_boto3() -> Any:
    """Get boto3 module, raising ImportError if not available."""
    if not AWS_AVAILABLE or _boto3 is None:
        raise ImportError("boto3 not installed. Install with: pip install envdrift[aws]")
    return _boto3


def _get_error_code(e: Exception) -> str:
    """Extract error code from AWS ClientError safely."""
    response = getattr(e, "response", None)
    if response is None:
        return ""
    error = response.get("Error", {}) if isinstance(response, dict) else {}
    return str(error.get("Code", ""))


# Error codes that mean "authenticated but not authorized" across operations.
_ACCESS_DENIED_CODES = ("AccessDeniedException", "UnauthorizedException")


def _map_aws_error(
    e: Exception,
    *,
    error_msg: str,
    not_found: tuple[str, str] | None = None,
    access_denied: tuple[tuple[str, ...], str] | None = None,
) -> Exception:
    """Translate a botocore/boto3 exception into a domain VaultError.

    Centralizes the catch-ladder shared by every AWS operation so each method
    delegates instead of repeating the `BotoCoreError`-then-error-code branches.
    `error_msg` is the generic prefix used for both transport failures and
    unclassified error codes (always the same text per call site):

    - `BotoCoreError` (transport/connectivity, no `.response`) -> ``VaultError``.
    - An error code matching `not_found` (code, message) -> ``SecretNotFoundError``.
    - An error code in `access_denied` (codes, message) -> ``AuthenticationError``.
    - Any other error code -> ``VaultError(error_msg)``.

    Returns the exception to raise, or re-raises ``e`` unchanged when it carries
    no recognizable error code (so the caller's ``raise`` semantics are preserved).
    """
    if isinstance(e, BotoCoreError):
        return VaultError(f"{error_msg}: {e}")
    error_code = _get_error_code(e)
    if not_found is not None and error_code == not_found[0]:
        return SecretNotFoundError(not_found[1])
    if access_denied is not None and error_code in access_denied[0]:
        return AuthenticationError(access_denied[1])
    if error_code:
        return VaultError(f"{error_msg}: {e}")
    raise e


class AWSSecretsManagerClient(VaultClient):
    """AWS Secrets Manager implementation.

    Uses boto3's default credential chain which supports:
    - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    - Shared credential file (~/.aws/credentials)
    - AWS config file (~/.aws/config)
    - IAM role credentials (EC2, ECS, Lambda)
    """

    def __init__(self, region: str = "us-east-1"):
        """Initialize AWS Secrets Manager client.

        Args:
            region: AWS region name
        """
        _get_boto3()  # Verify boto3 is available
        self.region = region
        self._client: Any = None

    def authenticate(self) -> None:
        """
        Initialize the AWS Secrets Manager client for the configured region and verify access.

        Raises:
            AuthenticationError: if AWS credentials are missing or incomplete.
            VaultError: if the Secrets Manager service returns an error.
        """
        boto3 = _get_boto3()
        try:
            self._client = boto3.client(
                "secretsmanager",
                region_name=self.region,
            )
            # Test authentication using get_caller_identity via STS
            # This is more reliable than list_secrets which requires extra permissions
            sts = boto3.client("sts", region_name=self.region)
            sts.get_caller_identity()
        except (NoCredentialsError, PartialCredentialsError) as e:
            raise AuthenticationError(f"AWS authentication failed: {e}") from e
        except Exception as e:
            # Transport failures (BotoCoreError, no `.response`) and credential
            # error codes both map to the domain hierarchy via the shared helper.
            raise _map_aws_error(
                e,
                error_msg="AWS Secrets Manager error",
                access_denied=(
                    ("AccessDenied", "InvalidClientTokenId"),
                    f"AWS authentication failed: {e}",
                ),
            ) from e

    def is_authenticated(self) -> bool:
        """
        Return whether the AWS Secrets Manager client has been authenticated.

        This method validates credentials by calling STS get_caller_identity(),
        which ensures that expired or revoked credentials are detected.

        Returns:
            `true` if the client is authenticated and credentials are valid, `false` otherwise.
        """
        if self._client is None:
            return False

        # Validate credentials are still valid by calling STS
        boto3 = _get_boto3()
        try:
            sts = boto3.client("sts", region_name=self.region)
            sts.get_caller_identity()
            return True
        except Exception:
            # Credentials are invalid/expired, reset client state
            self._client = None
            return False

    def get_secret(self, name: str) -> SecretValue:
        """
        Retrieve a secret from AWS Secrets Manager.

        Parameters:
            name (str): Secret name or ARN.

        Returns:
            SecretValue: The secret value.

        Raises:
            SecretNotFoundError: If the secret does not exist.
            AuthenticationError: If credentials are invalid.
            VaultError: On other AWS errors.
        """
        if self._client is None:
            raise VaultError("Not authenticated. Call authenticate() first.")

        try:
            response = self._client.get_secret_value(SecretId=name)
            version_id = response.get("VersionId")
            metadata = {"arn": response.get("ARN")}

            # SecretString contains the value, SecretBinary for binary secrets
            if "SecretString" in response:
                # Return the stored string byte-for-byte. Round-tripping
                # through json.loads/json.dumps would silently re-serialize
                # JSON-shaped values (e.g. "[1,2,3]" -> "[1, 2, 3]", losing
                # number/whitespace formatting), mutating the secret (#373).
                return SecretValue(
                    name=name,
                    value=response["SecretString"],
                    version=version_id,
                    metadata=metadata,
                )
            elif "SecretBinary" in response:
                # Binary secret - decode and return
                try:
                    value = response["SecretBinary"].decode("utf-8")
                except UnicodeDecodeError:
                    import base64

                    value = base64.b64encode(response["SecretBinary"]).decode("ascii")
                return SecretValue(
                    name=name,
                    value=value,
                    version=version_id,
                    metadata=metadata,
                )
            else:
                # Malformed response: neither SecretString nor SecretBinary.
                raise VaultError(
                    f"Malformed response for secret {name}: "
                    "missing both SecretString and SecretBinary"
                )
        except VaultError:
            # Already a domain error (e.g. malformed-response above); do not
            # re-wrap or misclassify it via the AWS error-code branches below.
            raise
        except Exception as e:
            raise _map_aws_error(
                e,
                error_msg=f"Failed to get secret {name}",
                not_found=("ResourceNotFoundException", f"Secret not found: {name}"),
                access_denied=(_ACCESS_DENIED_CODES, f"Access denied for secret: {name}"),
            ) from e

    def list_secrets(self, prefix: str = "") -> list[str]:
        """
        List all secret names available in the current AWS region.

        Parameters:
            prefix (str): Optional prefix to filter secrets by name.

        Returns:
            List of secret names.

        Raises:
            AuthenticationError: If credentials are invalid.
            VaultError: On other AWS errors.
        """
        if self._client is None:
            raise VaultError("Not authenticated. Call authenticate() first.")

        try:
            paginator = self._client.get_paginator("list_secrets")
            secret_names: list[str] = []

            for page in paginator.paginate():
                for secret in page.get("SecretList", []):
                    name = secret["Name"]
                    if not prefix or name.startswith(prefix):
                        secret_names.append(name)

            return sorted(secret_names)
        except Exception as e:
            raise _map_aws_error(
                e,
                error_msg="Failed to list secrets",
                access_denied=(_ACCESS_DENIED_CODES, "Access denied when listing secrets"),
            ) from e

    def _put_secret_value(self, name: str, value: str) -> SecretValue:
        """Update an existing secret value."""
        if self._client is None:
            raise VaultError("Not authenticated. Call authenticate() first.")

        try:
            response = self._client.put_secret_value(
                SecretId=name,
                SecretString=value,
            )
            return SecretValue(
                name=name,
                value=value,
                version=response.get("VersionId"),
                metadata={"arn": response.get("ARN")},
            )
        except Exception as e:
            raise _map_aws_error(
                e,
                error_msg=f"Failed to set secret {name}",
                access_denied=(_ACCESS_DENIED_CODES, f"Access denied for secret: {name}"),
            ) from e

    def set_secret(self, name: str, value: str) -> SecretValue:
        """
        Create or update a secret in AWS Secrets Manager.

        Parameters:
            name (str): Secret name.
            value (str): Secret value.

        Returns:
            SecretValue: The stored secret.

        Raises:
            AuthenticationError: If credentials are invalid.
            VaultError: On other AWS errors.
        """
        if self._client is None:
            raise VaultError("Not authenticated. Call authenticate() first.")

        try:
            # Try to create first
            response = self._client.create_secret(
                Name=name,
                SecretString=value,
            )
            return SecretValue(
                name=name,
                value=value,
                version=response.get("VersionId"),
                metadata={"arn": response.get("ARN")},
            )
        except Exception as e:
            # Secret already exists: fall back to updating its value. A genuine
            # create-permission denial must still surface (consistent with the
            # other entry points), so only ResourceExistsException short-circuits.
            if not isinstance(e, BotoCoreError) and _get_error_code(e) == "ResourceExistsException":
                return self._put_secret_value(name, value)
            raise _map_aws_error(
                e,
                error_msg=f"Failed to set secret {name}",
                access_denied=(_ACCESS_DENIED_CODES, f"Access denied for secret: {name}"),
            ) from e

    def set_secret_dict(self, name: str, value: dict[str, Any]) -> SecretValue:
        """
        Create or update a secret in AWS Secrets Manager with a dict value.

        Parameters:
            name (str): Secret name.
            value (dict): Secret value as a dictionary (stored as JSON).

        Returns:
            SecretValue: The stored secret.

        Raises:
            AuthenticationError: If credentials are invalid.
            VaultError: On other AWS errors.
        """
        return self.set_secret(name, json.dumps(value))
