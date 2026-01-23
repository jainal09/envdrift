"""Built-in secret detection patterns.

This module contains regex patterns for detecting common secrets in source code
and configuration files. Patterns are categorized by confidence level:

- CRITICAL_PATTERNS: High-confidence patterns with known secret formats
- HIGH_PATTERNS: Generic patterns that likely indicate secrets
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from envdrift.scanner.base import FindingSeverity


@dataclass(frozen=True)
class SecretPattern:
    """A regex pattern for detecting secrets.

    Attributes:
        id: Unique identifier for this pattern (e.g., "aws-access-key-id").
        description: Human-readable description of what this pattern detects.
        pattern: Compiled regex pattern. Should have a capture group for the secret.
        severity: Severity level when this pattern matches.
        keywords: Optional context keywords that increase confidence.
    """

    id: str
    description: str
    pattern: re.Pattern[str]
    severity: FindingSeverity
    keywords: tuple[str, ...] = ()


# High-confidence patterns - known secret formats with distinctive prefixes
CRITICAL_PATTERNS: list[SecretPattern] = [
    # AWS
    SecretPattern(
        id="aws-access-key-id",
        description="AWS Access Key ID",
        pattern=re.compile(r"(?:^|[^A-Z0-9])((AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})(?:[^A-Z0-9]|$)"),
        severity=FindingSeverity.CRITICAL,
        keywords=("aws", "amazon", "access_key", "access-key"),
    ),
    SecretPattern(
        id="aws-secret-access-key",
        description="AWS Secret Access Key",
        pattern=re.compile(
            r"(?i)(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key)"
            r"\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="aws-session-token",
        description="AWS Session Token",
        pattern=re.compile(
            r"(?i)(?:aws[_-]?session[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?"
        ),
        severity=FindingSeverity.CRITICAL,
    ),
    # GitHub
    SecretPattern(
        id="github-pat",
        description="GitHub Personal Access Token",
        pattern=re.compile(r"(ghp_[a-zA-Z0-9]{36})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="github-oauth",
        description="GitHub OAuth Access Token",
        pattern=re.compile(r"(gho_[a-zA-Z0-9]{36})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="github-app-token",
        description="GitHub App Token",
        pattern=re.compile(r"((?:ghu|ghs)_[a-zA-Z0-9]{36})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="github-refresh-token",
        description="GitHub Refresh Token",
        pattern=re.compile(r"(ghr_[a-zA-Z0-9]{36})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="github-fine-grained-pat",
        description="GitHub Fine-Grained Personal Access Token",
        pattern=re.compile(r"(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})"),
        severity=FindingSeverity.CRITICAL,
    ),
    # GitLab
    SecretPattern(
        id="gitlab-pat",
        description="GitLab Personal Access Token",
        pattern=re.compile(r"(glpat-[a-zA-Z0-9\-=_]{20,})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="gitlab-pipeline-token",
        description="GitLab Pipeline Trigger Token",
        pattern=re.compile(r"(glptt-[a-zA-Z0-9\-=_]{20,})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="gitlab-runner-token",
        description="GitLab Runner Registration Token",
        pattern=re.compile(r"(GR1348941[a-zA-Z0-9\-=_]{20,})"),
        severity=FindingSeverity.CRITICAL,
    ),
    # OpenAI / Anthropic
    SecretPattern(
        id="openai-api-key",
        description="OpenAI API Key",
        pattern=re.compile(r"(sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="openai-api-key-project",
        description="OpenAI Project API Key",
        pattern=re.compile(r"(sk-proj-[a-zA-Z0-9\-_]{80,})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="anthropic-api-key",
        description="Anthropic API Key",
        pattern=re.compile(r"(sk-ant-api03-[a-zA-Z0-9\-_]{93})"),
        severity=FindingSeverity.CRITICAL,
    ),
    # Slack
    SecretPattern(
        id="slack-bot-token",
        description="Slack Bot Token",
        pattern=re.compile(r"(xoxb-[0-9]{10,13}-[0-9]{10,13}(-[a-zA-Z0-9]{24})?)"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="slack-user-token",
        description="Slack User Token",
        pattern=re.compile(r"(xoxp-[0-9]{10,13}-[0-9]{10,13}(-[a-zA-Z0-9]{24})?)"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="slack-app-token",
        description="Slack App-Level Token",
        pattern=re.compile(r"(xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-zA-Z0-9]+)"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="slack-webhook",
        description="Slack Webhook URL",
        pattern=re.compile(
            r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+)"
        ),
        severity=FindingSeverity.CRITICAL,
    ),
    # Stripe
    SecretPattern(
        id="stripe-secret-key",
        description="Stripe Secret Key",
        pattern=re.compile(r"(sk_live_[a-zA-Z0-9]{24,})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="stripe-restricted-key",
        description="Stripe Restricted API Key",
        pattern=re.compile(r"(rk_live_[a-zA-Z0-9]{24,})"),
        severity=FindingSeverity.CRITICAL,
    ),
    # Google
    SecretPattern(
        id="google-api-key",
        description="Google API Key",
        pattern=re.compile(r"(AIza[0-9A-Za-z_-]{35})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="google-oauth-client-secret",
        description="Google OAuth Client Secret",
        pattern=re.compile(r"(GOCSPX-[a-zA-Z0-9_-]{28})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="gcp-service-account",
        description="GCP Service Account Key",
        pattern=re.compile(r'"type"\s*:\s*"service_account".*"private_key"\s*:\s*"-----BEGIN'),
        severity=FindingSeverity.CRITICAL,
    ),
    # Azure
    SecretPattern(
        id="azure-storage-key",
        description="Azure Storage Account Key",
        pattern=re.compile(
            r"(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*([a-zA-Z0-9+/=]{88})"
        ),
        severity=FindingSeverity.CRITICAL,
    ),
    # Twilio
    SecretPattern(
        id="twilio-api-key",
        description="Twilio API Key",
        pattern=re.compile(r"(SK[a-fA-F0-9]{32})"),
        severity=FindingSeverity.HIGH,
        keywords=("twilio",),
    ),
    SecretPattern(
        id="twilio-account-sid",
        description="Twilio Account SID",
        pattern=re.compile(r"(AC[a-fA-F0-9]{32})"),
        severity=FindingSeverity.HIGH,
        keywords=("twilio",),
    ),
    # SendGrid
    SecretPattern(
        id="sendgrid-api-key",
        description="SendGrid API Key",
        pattern=re.compile(r"(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})"),
        severity=FindingSeverity.CRITICAL,
    ),
    # Mailchimp
    SecretPattern(
        id="mailchimp-api-key",
        description="Mailchimp API Key",
        pattern=re.compile(r"([a-f0-9]{32}-us[0-9]{1,2})"),
        severity=FindingSeverity.HIGH,
        keywords=("mailchimp",),
    ),
    # NPM
    SecretPattern(
        id="npm-token",
        description="NPM Access Token",
        pattern=re.compile(r"(npm_[a-zA-Z0-9]{36})"),
        severity=FindingSeverity.CRITICAL,
    ),
    # PyPI
    SecretPattern(
        id="pypi-token",
        description="PyPI API Token",
        pattern=re.compile(r"(pypi-[a-zA-Z0-9_-]{50,})"),
        severity=FindingSeverity.CRITICAL,
    ),
    # Private Keys
    SecretPattern(
        id="private-key-rsa",
        description="RSA Private Key",
        pattern=re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="private-key-openssh",
        description="OpenSSH Private Key",
        pattern=re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="private-key-ec",
        description="EC Private Key",
        pattern=re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="private-key-dsa",
        description="DSA Private Key",
        pattern=re.compile(r"-----BEGIN DSA PRIVATE KEY-----"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="private-key-generic",
        description="Private Key",
        pattern=re.compile(r"-----BEGIN PRIVATE KEY-----"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="pgp-private-key",
        description="PGP Private Key Block",
        pattern=re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        severity=FindingSeverity.CRITICAL,
    ),
    # Discord
    SecretPattern(
        id="discord-bot-token",
        description="Discord Bot Token",
        pattern=re.compile(r"([MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27})"),
        severity=FindingSeverity.HIGH,
        keywords=("discord",),
    ),
    SecretPattern(
        id="discord-webhook",
        description="Discord Webhook URL",
        pattern=re.compile(r"(https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+)"),
        severity=FindingSeverity.CRITICAL,
    ),
    # Telegram
    SecretPattern(
        id="telegram-bot-token",
        description="Telegram Bot Token",
        pattern=re.compile(r"([0-9]{8,10}:[a-zA-Z0-9_-]{35})"),
        severity=FindingSeverity.HIGH,
        keywords=("telegram", "bot"),
    ),
    # Heroku
    SecretPattern(
        id="heroku-api-key",
        description="Heroku API Key",
        pattern=re.compile(
            r"(?i)(?:heroku[_-]?api[_-]?key)\s*[=:]\s*['\"]?"
            r"([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]?"
        ),
        severity=FindingSeverity.CRITICAL,
    ),
    # Datadog
    SecretPattern(
        id="datadog-api-key",
        description="Datadog API Key",
        pattern=re.compile(
            r"(?i)(?:datadog[_-]?api[_-]?key|dd[_-]?api[_-]?key)\s*[=:]\s*['\"]?"
            r"([a-f0-9]{32})['\"]?"
        ),
        severity=FindingSeverity.HIGH,
        keywords=("datadog",),
    ),
    # Slack Configuration Token (for App Manifest APIs)
    SecretPattern(
        id="slack-config-token",
        description="Slack Configuration Token",
        pattern=re.compile(r"(xoxe\.xox[bp]-[0-9]+-[a-zA-Z0-9]+)"),
        severity=FindingSeverity.CRITICAL,
    ),
    # Mailgun - format is not officially documented, require keyword context
    SecretPattern(
        id="mailgun-api-key",
        description="Mailgun API Key",
        pattern=re.compile(
            r"(?i)mailgun[_-]?(?:api[_-]?)?key\s*[=:]\s*['\"]?([a-zA-Z0-9-]{32,})['\"]?"
        ),
        severity=FindingSeverity.CRITICAL,
        keywords=("mailgun",),
    ),
    # Twilio additional patterns
    SecretPattern(
        id="twilio-app-sid",
        description="Twilio Application SID",
        pattern=re.compile(r"(AP[a-fA-F0-9]{32})"),
        severity=FindingSeverity.HIGH,
        keywords=("twilio",),
    ),
    # Square (legacy format - modern tokens are opaque bearer strings)
    # These patterns detect older sq0atp/sq0csp prefixed tokens
    SecretPattern(
        id="square-access-token",
        description="Square Access Token (Legacy Format)",
        pattern=re.compile(r"(sq0atp-[a-zA-Z0-9_-]{22,})"),
        severity=FindingSeverity.CRITICAL,
        keywords=("square",),
    ),
    SecretPattern(
        id="square-oauth-secret",
        description="Square OAuth Secret (Legacy Format)",
        pattern=re.compile(r"(sq0csp-[a-zA-Z0-9_-]{40,})"),
        severity=FindingSeverity.CRITICAL,
        keywords=("square",),
    ),
    # Braintree/PayPal
    SecretPattern(
        id="braintree-access-token",
        description="Braintree Access Token",
        pattern=re.compile(r"(access_token\$(?:production|sandbox)\$[a-z0-9]+\$[a-f0-9]{32})"),
        severity=FindingSeverity.CRITICAL,
    ),
    # Facebook - tokens are opaque strings, commonly start with EAA but can vary
    SecretPattern(
        id="facebook-access-token",
        description="Facebook Access Token",
        pattern=re.compile(r"(EAA[a-zA-Z0-9]{50,})"),
        severity=FindingSeverity.CRITICAL,
        keywords=("facebook", "fb", "graph"),
    ),
    # PuTTY private key
    SecretPattern(
        id="putty-private-key",
        description="PuTTY Private Key",
        pattern=re.compile(r"(PuTTY-User-Key-File-[0-9]+:[^\n]+)"),
        severity=FindingSeverity.CRITICAL,
    ),
    # GitHub App Client ID
    SecretPattern(
        id="github-app-client-id",
        description="GitHub App Client ID",
        pattern=re.compile(r"(Iv1\.[a-f0-9]{16})"),
        severity=FindingSeverity.HIGH,
        keywords=("github",),
    ),
    # Google reCAPTCHA secret
    SecretPattern(
        id="google-recaptcha-secret",
        description="Google reCAPTCHA Secret",
        pattern=re.compile(r"(6L[a-zA-Z0-9_-]{38})"),
        severity=FindingSeverity.HIGH,
        keywords=("recaptcha", "captcha"),
    ),
]

# Mixed-confidence patterns - patterns with varying severity levels
HIGH_PATTERNS: list[SecretPattern] = [
    # JWT - medium severity because JWTs are often meant to be shared
    SecretPattern(
        id="jwt-token",
        description="JSON Web Token",
        pattern=re.compile(r"(eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)"),
        severity=FindingSeverity.MEDIUM,
    ),
    SecretPattern(
        id="generic-api-key",
        description="Generic API Key",
        pattern=re.compile(r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?"),
        severity=FindingSeverity.HIGH,
    ),
    SecretPattern(
        id="generic-secret",
        description="Generic Secret",
        pattern=re.compile(
            r"(?i)\b(?:secret|token|password|passwd|pwd|auth[_-]?token)"
            r"\s*[=:]\s*['\"]?([a-zA-Z0-9_!@#$%^&*(),.?\":{}|<>\[\]\\;'`~\-+=]{8,})['\"]?"
        ),
        severity=FindingSeverity.HIGH,
    ),
    SecretPattern(
        id="basic-auth-header",
        description="Basic Auth Header",
        pattern=re.compile(r"(?i)authorization\s*[=:]\s*['\"]?basic\s+([a-zA-Z0-9+/=]+)['\"]?"),
        severity=FindingSeverity.HIGH,
    ),
    SecretPattern(
        id="bearer-token-header",
        description="Bearer Token",
        pattern=re.compile(r"(?i)authorization\s*[=:]\s*['\"]?bearer\s+([a-zA-Z0-9._-]+)['\"]?"),
        severity=FindingSeverity.HIGH,
    ),
    SecretPattern(
        id="database-url-postgres",
        description="PostgreSQL Connection String",
        pattern=re.compile(r"(?i)postgres(?:ql)?://[^:]+:([^@]+)@[^\s]+"),
        severity=FindingSeverity.HIGH,
    ),
    SecretPattern(
        id="database-url-mysql",
        description="MySQL Connection String",
        pattern=re.compile(r"(?i)mysql://[^:]+:([^@]+)@[^\s]+"),
        severity=FindingSeverity.HIGH,
    ),
    SecretPattern(
        id="database-url-mongodb",
        description="MongoDB Connection String",
        pattern=re.compile(r"(?i)mongodb(?:\+srv)?://[^:]+:([^@]+)@[^\s]+"),
        severity=FindingSeverity.HIGH,
    ),
    SecretPattern(
        id="redis-url",
        description="Redis Connection String",
        pattern=re.compile(r"(?i)redis://(?:[^:]+:)?([^@]+)@[^\s]+"),
        severity=FindingSeverity.HIGH,
    ),
    # Password hashes (dangerous if leaked)
    SecretPattern(
        id="bcrypt-hash",
        description="Bcrypt Password Hash",
        pattern=re.compile(r"(\$2[ayb]\$[0-9]{2}\$[a-zA-Z0-9./]{53})"),
        severity=FindingSeverity.HIGH,
    ),
    SecretPattern(
        id="sha512crypt-hash",
        description="SHA-512 Crypt Password Hash",
        pattern=re.compile(r"(\$6\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{86})"),
        severity=FindingSeverity.HIGH,
    ),
    # Docker registry auth
    SecretPattern(
        id="docker-auth",
        description="Docker Registry Auth",
        pattern=re.compile(r'"auth"\s*:\s*"([a-zA-Z0-9+/=]{20,})"'),
        severity=FindingSeverity.HIGH,
    ),
    # NPM auth tokens (must start with _auth specifically, not just end with auth)
    SecretPattern(
        id="npmrc-auth",
        description="NPM Auth Token (.npmrc)",
        pattern=re.compile(r"(?m)^_auth\s*=\s*([a-zA-Z0-9+/=]{20,})"),
        severity=FindingSeverity.HIGH,
    ),
    SecretPattern(
        id="npmrc-authtoken",
        description="NPM Auth Token (.npmrc)",
        pattern=re.compile(r"(?i):_authToken\s*=\s*([a-zA-Z0-9-]+)"),
        severity=FindingSeverity.HIGH,
    ),
    # Git credentials
    SecretPattern(
        id="git-credentials",
        description="Git Credentials URL",
        pattern=re.compile(r"https?://[^:]+:([^@\s]+)@(?:github|gitlab|bitbucket)"),
        severity=FindingSeverity.CRITICAL,
    ),
    # Laravel APP_KEY
    SecretPattern(
        id="laravel-app-key",
        description="Laravel Application Key",
        pattern=re.compile(r"(?i)APP_KEY\s*=\s*['\"]?(base64:[a-zA-Z0-9+/=]{43,44})['\"]?"),
        severity=FindingSeverity.HIGH,
    ),
    # Django SECRET_KEY
    SecretPattern(
        id="django-secret-key",
        description="Django Secret Key",
        pattern=re.compile(r"(?i)SECRET_KEY\s*=\s*['\"]([^'\"]{40,})['\"]"),
        severity=FindingSeverity.HIGH,
    ),
    # WordPress salts/keys
    SecretPattern(
        id="wordpress-auth-key",
        description="WordPress Authentication Key",
        pattern=re.compile(
            r"(?i)define\s*\(\s*['\"](?:AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|"
            r"AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)['\"]"
            r"\s*,\s*['\"]([^'\"]{30,})['\"]"
        ),
        severity=FindingSeverity.HIGH,
    ),
    # Database password in define() - PHP style
    SecretPattern(
        id="php-db-password",
        description="PHP Database Password",
        pattern=re.compile(r"(?i)define\s*\(\s*['\"]DB_PASSWORD['\"]?\s*,\s*['\"]([^'\"]+)['\"]"),
        severity=FindingSeverity.HIGH,
    ),
    # Connection string with password (require semicolon delimiter for connection strings)
    SecretPattern(
        id="connection-string-password",
        description="Connection String with Password",
        # Match: Password=value; (connection string style with semicolon)
        pattern=re.compile(r"(?i)(?:password|pwd)\s*=\s*([^;'\"\s]{4,});"),
        severity=FindingSeverity.HIGH,
    ),
    # FTP/SFTP password in config files
    SecretPattern(
        id="ftp-password",
        description="FTP/SFTP Password",
        pattern=re.compile(r'"(?:password|pass|passphrase)"\s*:\s*"([^"]+)"'),
        severity=FindingSeverity.HIGH,
    ),
    # Generic credentials in XML
    SecretPattern(
        id="xml-password",
        description="Password in XML",
        pattern=re.compile(r"<(?:password|passwd|pass|secret)>([^<]+)</"),
        severity=FindingSeverity.HIGH,
    ),
    # Base64 encoded auth (like _auth in .npmrc or Docker)
    SecretPattern(
        id="base64-auth-token",
        description="Base64 Encoded Auth",
        pattern=re.compile(
            r"(?i)(?:_auth|auth|authorization)\s*[=:]\s*['\"]?([A-Za-z0-9+/]{40,}={0,2})['\"]?"
        ),
        severity=FindingSeverity.MEDIUM,
    ),
    # Hashicorp Vault Token
    SecretPattern(
        id="vault-token",
        description="Hashicorp Vault Token",
        pattern=re.compile(r"(hvs\.[a-zA-Z0-9_-]{24,})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="vault-batch-token",
        description="Hashicorp Vault Batch Token",
        pattern=re.compile(r"(hvb\.[a-zA-Z0-9_-]{24,})"),
        severity=FindingSeverity.CRITICAL,
    ),
    # Shopify
    SecretPattern(
        id="shopify-access-token",
        description="Shopify Access Token",
        pattern=re.compile(r"(shpat_[a-fA-F0-9]{32})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="shopify-shared-secret",
        description="Shopify Shared Secret",
        pattern=re.compile(r"(shpss_[a-fA-F0-9]{32})"),
        severity=FindingSeverity.CRITICAL,
    ),
    # Atlassian / Jira / Confluence
    SecretPattern(
        id="atlassian-api-token",
        description="Atlassian API Token",
        pattern=re.compile(
            r"(?i)(?:atlassian|jira|confluence)[_-]?(?:api[_-]?)?token\s*[=:]\s*['\"]?([a-zA-Z0-9]{24})['\"]?"
        ),
        severity=FindingSeverity.HIGH,
    ),
    # Sentry DSN (contains secret key)
    SecretPattern(
        id="sentry-dsn",
        description="Sentry DSN",
        pattern=re.compile(r"(https://[a-f0-9]{32}@[a-z0-9.-]+\.ingest\.sentry\.io/[0-9]+)"),
        severity=FindingSeverity.HIGH,
    ),
    # Linear API Key
    SecretPattern(
        id="linear-api-key",
        description="Linear API Key",
        pattern=re.compile(r"(lin_api_[a-zA-Z0-9]{40})"),
        severity=FindingSeverity.CRITICAL,
    ),
    # Vercel Token
    SecretPattern(
        id="vercel-token",
        description="Vercel Token",
        pattern=re.compile(r"(?i)vercel[_-]?token\s*[=:]\s*['\"]?([a-zA-Z0-9]{24})['\"]?"),
        severity=FindingSeverity.HIGH,
    ),
    # Netlify Token
    SecretPattern(
        id="netlify-token",
        description="Netlify Token",
        pattern=re.compile(
            r"(?i)netlify[_-]?(?:auth[_-]?)?token\s*[=:]\s*['\"]?([a-zA-Z0-9_-]{40,})['\"]?"
        ),
        severity=FindingSeverity.HIGH,
    ),
    # Cloudflare API Token
    SecretPattern(
        id="cloudflare-api-token",
        description="Cloudflare API Token",
        pattern=re.compile(
            r"(?i)cloudflare[_-]?(?:api[_-]?)?token\s*[=:]\s*['\"]?([a-zA-Z0-9_-]{40})['\"]?"
        ),
        severity=FindingSeverity.HIGH,
    ),
    # DigitalOcean
    SecretPattern(
        id="digitalocean-token",
        description="DigitalOcean Token",
        pattern=re.compile(r"(dop_v1_[a-f0-9]{64})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="digitalocean-oauth",
        description="DigitalOcean OAuth Token",
        pattern=re.compile(r"(doo_v1_[a-f0-9]{64})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="digitalocean-refresh",
        description="DigitalOcean Refresh Token",
        pattern=re.compile(r"(dor_v1_[a-f0-9]{64})"),
        severity=FindingSeverity.CRITICAL,
    ),
    # Doppler
    SecretPattern(
        id="doppler-token",
        description="Doppler Token",
        pattern=re.compile(r"(dp\.(?:ct|st|sa|scim)\.[a-zA-Z0-9]{40,44})"),
        severity=FindingSeverity.CRITICAL,
    ),
    # Supabase
    SecretPattern(
        id="supabase-key",
        description="Supabase API Key",
        pattern=re.compile(r"(sbp_[a-f0-9]{40})"),
        severity=FindingSeverity.CRITICAL,
    ),
    # Postman API Key
    SecretPattern(
        id="postman-api-key",
        description="Postman API Key",
        pattern=re.compile(r"(PMAK-[a-f0-9]{24}-[a-f0-9]{34})"),
        severity=FindingSeverity.CRITICAL,
    ),
    # New Relic
    SecretPattern(
        id="newrelic-license-key",
        description="New Relic License Key",
        pattern=re.compile(
            r"(?i)new[_-]?relic[_-]?license[_-]?key\s*[=:]\s*['\"]?([a-f0-9]{40})['\"]?"
        ),
        severity=FindingSeverity.HIGH,
    ),
    # Algolia
    SecretPattern(
        id="algolia-api-key",
        description="Algolia API Key",
        pattern=re.compile(r"(?i)algolia[_-]?(?:api[_-]?)?key\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?"),
        severity=FindingSeverity.HIGH,
    ),
]

# Combined list of all patterns
ALL_PATTERNS: list[SecretPattern] = CRITICAL_PATTERNS + HIGH_PATTERNS


def redact_secret(secret: str, visible_chars: int = 4) -> str:
    """Redact a secret, showing only first and last few characters.

    Args:
        secret: The secret string to redact.
        visible_chars: Number of characters to show at start and end.

    Returns:
        Redacted string like "AKIA****MPLE".
    """
    if len(secret) <= visible_chars * 2:
        return "*" * len(secret)
    return f"{secret[:visible_chars]}{'*' * (len(secret) - visible_chars * 2)}{secret[-visible_chars:]}"


def hash_secret(secret: str) -> str:
    """Compute a SHA-256 hash of a secret for deduplication.

    This allows accurate deduplication by secret value without storing
    the plaintext secret. Two identical secrets will produce the same hash.

    Args:
        secret: The secret string to hash.

    Returns:
        Hex-encoded SHA-256 hash of the secret.
    """
    import hashlib

    return hashlib.sha256(secret.encode()).hexdigest()


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string.

    Higher entropy indicates more randomness, which is characteristic of secrets.
    Typical thresholds:
    - < 3.0: Low entropy (common words, patterns)
    - 3.0-4.0: Medium entropy
    - 4.0-5.0: High entropy (possible secrets)
    - > 5.0: Very high entropy (likely secrets)

    Args:
        text: The string to analyze.

    Returns:
        Shannon entropy value (bits per character).
    """
    import math

    if not text:
        return 0.0

    freq: dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    length = len(text)
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)

    return entropy
