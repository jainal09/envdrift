"""AWS Secrets Manager client implementation."""

from __future__ import annotations

import json

from envdrift.vault.base import (
    AuthenticationError,
    SecretNotFoundError,
    SecretValue,
    VaultClient,
    VaultError,
)

try:
    import boto3
    from botocore.exceptions import (
        ClientError,
        NoCredentialsError,
        PartialCredentialsError,
    )

    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False
    boto3 = None
    ClientError = Exception
    NoCredentialsError = Exception
    PartialCredentialsError = Exception


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
        if not AWS_AVAILABLE:
            raise ImportError("boto3 not installed. Install with: pip install envdrift[aws]")

        self.region = region
        self._client = None

    def authenticate(self) -> None:
        """
        Initialize the AWS Secrets Manager client for the configured region and verify access.

        Raises:
            AuthenticationError: if AWS credentials are missing or incomplete.
            VaultError: if the Secrets Manager service returns an error.
        """
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
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("AccessDenied", "InvalidClientTokenId"):
                raise AuthenticationError(f"AWS authentication failed: {e}") from e
            raise VaultError(f"AWS Secrets Manager error: {e}") from e

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
        try:
            sts = boto3.client("sts", region_name=self.region)
            sts.get_caller_identity()
            return True
        except (NoCredentialsError, PartialCredentialsError, ClientError):
            # Credentials are invalid/expired, reset client state
            self._client = None
            return False

    def get_secret(self, name: str) -> SecretValue:
        """
        Retrieve a secret from AWS Secrets Manager.

        Parameters:
            name (str): Secret name or ARN.

        Returns:
            SecretValue: Contains the secret's name, value, version, and metadata (`arn`, `created_date`, `version_stages`).

        Raises:
            SecretNotFoundError: If the secret does not exist.
            VaultError: For other AWS Secrets Manager errors.
        """
        self.ensure_authenticated()

        try:
            response = self._client.get_secret_value(SecretId=name)

            # Secret can be string or binary
            if "SecretString" in response:
                value = response["SecretString"]
            else:
                # Binary secrets - try UTF-8, fall back to base64
                try:
                    value = response["SecretBinary"].decode("utf-8")
                except UnicodeDecodeError:
                    import base64

                    value = base64.b64encode(response["SecretBinary"]).decode("ascii")

            created = response.get("CreatedDate")
            created_str = str(created) if created else None
            return SecretValue(
                name=response.get("Name", name),
                value=value,
                version=response.get("VersionId"),
                metadata={
                    "arn": response.get("ARN"),
                    "created_date": created_str,
                    "version_stages": response.get("VersionStages", []),
                },
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "ResourceNotFoundException":
                raise SecretNotFoundError(f"Secret '{name}' not found") from e
            raise VaultError(f"AWS Secrets Manager error: {e}") from e

    def list_secrets(self, prefix: str = "") -> list[str]:
        """
        List secret names stored in AWS Secrets Manager.

        Parameters:
            prefix (str): Optional name prefix to filter results; only secrets whose names start with this prefix are returned.

        Returns:
            List of secret names.
        """
        self.ensure_authenticated()

        try:
            secrets = []
            paginator = self._client.get_paginator("list_secrets")

            # Note: AWS ListSecrets filter with Key="name" performs exact match,
            # so we fetch all secrets and filter client-side for prefix matching
            for page in paginator.paginate():
                for secret in page.get("SecretList", []):
                    name = secret.get("Name")
                    if name:
                        # Apply client-side prefix filtering
                        if not prefix or name.startswith(prefix):
                            secrets.append(name)

            return sorted(secrets)
        except ClientError as e:
            raise VaultError(f"AWS Secrets Manager error: {e}") from e

    def get_secret_json(self, name: str) -> dict:
        """
        Retrieve the secret identified by `name` and parse its value as a JSON object.

        Returns:
            dict: Parsed JSON from the secret value.

        Raises:
            VaultError: If the secret value is not valid JSON.
        """
        secret = self.get_secret(name)
        try:
            return json.loads(secret.value)
        except json.JSONDecodeError as e:
            raise VaultError(f"Secret '{name}' is not valid JSON: {e}") from e

    def create_secret(self, name: str, value: str, description: str = "") -> SecretValue:
        """
        Create a new secret in AWS Secrets Manager.

        Parameters:
            name (str): The name to assign to the secret.
            value (str): The secret value to store.
            description (str): Optional human-readable description for the secret.

        Returns:
            SecretValue: The created secret's representation, including the stored value, version identifier, and metadata (ARN).

        Raises:
            VaultError: If AWS Secrets Manager returns an error while creating the secret.
        """
        self.ensure_authenticated()

        try:
            response = self._client.create_secret(
                Name=name,
                SecretString=value,
                Description=description,
            )
            return SecretValue(
                name=response.get("Name", name),
                value=value,
                version=response.get("VersionId"),
                metadata={"arn": response.get("ARN")},
            )
        except ClientError as e:
            raise VaultError(f"AWS Secrets Manager error: {e}") from e

    def update_secret(self, name: str, value: str) -> SecretValue:
        """
        Update an existing secret in AWS Secrets Manager.

        Returns:
            SecretValue: Contains the updated secret's name, value, version, and ARN metadata.

        Raises:
            VaultError: If AWS Secrets Manager returns an error.
        """
        self.ensure_authenticated()

        try:
            response = self._client.put_secret_value(
                SecretId=name,
                SecretString=value,
            )
            return SecretValue(
                name=response.get("Name", name),
                value=value,
                version=response.get("VersionId"),
                metadata={"arn": response.get("ARN")},
            )
        except ClientError as e:
            raise VaultError(f"AWS Secrets Manager error: {e}") from e
