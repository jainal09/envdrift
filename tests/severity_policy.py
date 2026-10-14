"""The cross-scanner severity policy, encoded once.

A credential class gets the same severity from every scanner that grades by credential
class, and the native scanner's grade is the reference. ``POLICY`` lists each class with
the severity it must have, and the identifiers every such scanner uses for it:

* ``native``: ids in ``envdrift.scanner.patterns`` (and ``high-entropy-string``)
* ``rules``: rule IDs of gitleaks and Infisical, graded by ``rule_severity``. Kingfisher
  grades its ``betterleaks.<id>`` rules through the same table.
* ``detect_secrets``: the ``type`` names of detect-secrets 1.5.0, keys of ``DETECTOR_SEVERITY``
* ``kingfisher``: the keywords ``kingfisher._map_severity`` matches in the ID or name of a rule
  that is not betterleaks'
* ``git_secrets``: the rule types of ``git_secrets.RULE_TYPE_SEVERITY``
* ``rule_patterns``: globs for the rule IDs of the class's providers in the real tools, so a
  test can tell when a rule of such a provider is missing from the table (see
  ``WAIVED_RULES``)

trufflehog, trivy and talisman are not here: trufflehog grades by whether a secret was
verified, and trivy and talisman pass their own tools' severities through, so envdrift has
no per-class table for them (see "Severity" in docs/cli/guard.md).

``tests/scanner/test_severity_policy.py`` checks every scanner's table against this module,
and ``tests/integration/test_severity_policy_real.py`` checks real scanner output against it,
so an edit to one table that drifts from the policy fails a test. To change a grade, change it
here and in every table that lists the class.

The rule IDs, detector names and sample files were taken from real runs: gitleaks 8.30.1,
Infisical 0.43.135 (the gitleaks engine) and 0.43.141 (betterleaks), and detect-secrets 1.5.0.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from envdrift.scanner.base import FindingSeverity

CRITICAL = FindingSeverity.CRITICAL
HIGH = FindingSeverity.HIGH
MEDIUM = FindingSeverity.MEDIUM


@dataclass(frozen=True)
class CredentialClass:
    """One credential class, the severity every scanner must give it, and its identifiers."""

    name: str
    severity: FindingSeverity
    native: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()
    detect_secrets: tuple[str, ...] = ()
    kingfisher: tuple[str, ...] = ()
    git_secrets: tuple[str, ...] = ()
    rule_patterns: tuple[str, ...] = ()


POLICY: tuple[CredentialClass, ...] = (
    # --- Cloud providers: CRITICAL
    CredentialClass(
        "aws",
        CRITICAL,
        native=("aws-access-key-id", "aws-secret-access-key", "aws-session-token"),
        rules=(
            "aws-access-token",
            "aws-secret-access-key",
            "aws-access-key-id",
            "aws-amazon-bedrock-api-key-long-lived",
            "aws-amazon-bedrock-api-key-short-lived",
            "aws-session-token",
        ),
        detect_secrets=("AWS Access Key",),
        kingfisher=("aws",),
        git_secrets=("aws-access-key", "aws-secret-key"),
        rule_patterns=("aws-*",),
    ),
    CredentialClass(
        "azure-storage-key",
        CRITICAL,
        native=("azure-storage-key",),
        rules=(
            "azure-storage-account-key",
            "azure-app-configuration-connection-string",
            "azure-servicebus-connection-string",
        ),
        detect_secrets=("Azure Storage Account access key",),
        kingfisher=("azure",),
        rule_patterns=("azure-*",),
    ),
    CredentialClass("azure-ad-client-secret", CRITICAL, rules=("azure-ad-client-secret",)),
    CredentialClass(
        "gcp-service-account",
        CRITICAL,
        native=("gcp-service-account",),
        rules=("gcp-service-account", "gcp-application-default-credentials"),
        kingfisher=("gcp",),
        rule_patterns=("gcp-*",),
    ),
    CredentialClass(
        "google-api-key",
        CRITICAL,
        native=("google-api-key",),
        rules=("gcp-api-key", "google-api-key", "gcp-gemini-api"),
    ),
    CredentialClass("google-oauth-client-secret", CRITICAL, native=("google-oauth-client-secret",)),
    CredentialClass(
        "ibm-cloud-iam-key",
        CRITICAL,
        rules=("ibm-cloud-user-api-key",),
        detect_secrets=("IBM Cloud IAM Key",),
        kingfisher=("ibm",),
        rule_patterns=("ibm-*",),
    ),
    CredentialClass(
        "cloudant-credentials",
        CRITICAL,
        detect_secrets=("Cloudant Credentials",),
        kingfisher=("cloudant",),
    ),
    CredentialClass("ibm-cos-hmac", CRITICAL, detect_secrets=("IBM COS HMAC Credentials",)),
    CredentialClass(
        "softlayer-credentials",
        CRITICAL,
        detect_secrets=("SoftLayer Credentials",),
        kingfisher=("softlayer",),
    ),
    # --- Source control, package registries and secret stores: CRITICAL
    CredentialClass(
        "github-token",
        CRITICAL,
        native=(
            "github-pat",
            "github-oauth",
            "github-app-token",
            "github-refresh-token",
            "github-fine-grained-pat",
        ),
        rules=(
            "github-pat",
            "github-oauth",
            "github-app-token",
            "github-refresh-token",
            "github-fine-grained-pat",
        ),
        detect_secrets=("GitHub Token",),
        kingfisher=("github",),
        rule_patterns=("github-*",),
    ),
    CredentialClass(
        "gitlab-token",
        CRITICAL,
        native=("gitlab-pat", "gitlab-pipeline-token", "gitlab-runner-token"),
        rules=(
            "gitlab-pat",
            "gitlab-pat-routable",
            "gitlab-pat-routable-versioned",
            "gitlab-ptt",
            "gitlab-rrt",
            "gitlab-runner-authentication-token",
            "gitlab-runner-authentication-token-routable",
            "gitlab-cicd-job-token",
            "gitlab-deploy-token",
            "gitlab-feature-flag-client-token",
            "gitlab-feed-token",
            "gitlab-incoming-mail-address-token",
            "gitlab-incoming-mail-token",
            "gitlab-kubernetes-agent-token",
            "gitlab-oauth-app-secret",
            "gitlab-scim-token",
            "gitlab-session-cookie",
        ),
        detect_secrets=("GitLab Token",),
        kingfisher=("gitlab",),
        rule_patterns=("gitlab-*",),
    ),
    CredentialClass(
        "npm-token",
        CRITICAL,
        native=("npm-token",),
        rules=("npm-access-token",),
        detect_secrets=("NPM tokens",),
        kingfisher=("npm",),
        rule_patterns=("npm-*",),
    ),
    CredentialClass(
        "pypi-token",
        CRITICAL,
        native=("pypi-token",),
        rules=("pypi-upload-token",),
        detect_secrets=("PyPI Token",),
        kingfisher=("pypi",),
        rule_patterns=("pypi-*",),
    ),
    CredentialClass(
        "vault-token",
        CRITICAL,
        native=("vault-token", "vault-batch-token"),
        rules=("vault-service-token", "vault-batch-token"),
        kingfisher=("vault",),
        rule_patterns=("vault-*",),
    ),
    CredentialClass(
        "private-key",
        CRITICAL,
        native=(
            "private-key-rsa",
            "private-key-openssh",
            "private-key-ec",
            "private-key-dsa",
            "private-key-generic",
            "pgp-private-key",
            "putty-private-key",
        ),
        rules=("private-key", "age-secret-key", "polymarket-private-key"),
        detect_secrets=("Private Key",),
        kingfisher=("privatekey", "private-key", "private_key"),
        git_secrets=("private-key",),
        rule_patterns=("private-key*", "*-private-key", "age-secret-key"),
    ),
    CredentialClass(
        "password-hash",
        CRITICAL,
        native=("bcrypt-hash", "sha512crypt-hash"),
        kingfisher=("password-hash", "password_hash", "bcrypt", "sha512crypt", "shadow"),
    ),
    CredentialClass("netrc-credentials", CRITICAL, kingfisher=("netrc",)),
    CredentialClass("git-credentials", CRITICAL, native=("git-credentials",)),
    # --- Payments, messaging and SaaS API keys: CRITICAL
    CredentialClass(
        "stripe-live-key",
        CRITICAL,
        native=("stripe-secret-key", "stripe-restricted-key"),
        rules=("stripe-access-token", "stripe-api-key"),
        detect_secrets=("Stripe Access Key",),
        kingfisher=("stripe",),
        rule_patterns=("stripe-*",),
    ),
    CredentialClass(
        "square-token",
        CRITICAL,
        native=("square-access-token", "square-oauth-secret"),
        rules=("square-access-token",),
        detect_secrets=("Square OAuth Secret",),
        kingfisher=("square",),
        rule_patterns=("square-*",),
    ),
    CredentialClass("braintree-access-token", CRITICAL, native=("braintree-access-token",)),
    CredentialClass(
        "slack-token",
        CRITICAL,
        native=(
            "slack-bot-token",
            "slack-user-token",
            "slack-app-token",
            "slack-config-token",
            "slack-webhook",
        ),
        rules=(
            "slack-bot-token",
            "slack-user-token",
            "slack-app-token",
            "slack-legacy-bot-token",
            "slack-legacy-token",
            "slack-legacy-workspace-token",
            "slack-config-access-token",
            "slack-config-refresh-token",
            "slack-session-cookie",
            "slack-session-token",
            "slack-webhook-url",
            "slack-token",
        ),
        detect_secrets=("Slack Token",),
        kingfisher=("slack",),
        rule_patterns=("slack-*",),
    ),
    CredentialClass(
        "sendgrid-api-key",
        CRITICAL,
        native=("sendgrid-api-key",),
        rules=("sendgrid-api-token",),
        detect_secrets=("SendGrid API Key",),
        kingfisher=("sendgrid",),
        rule_patterns=("sendgrid-*",),
    ),
    CredentialClass(
        "openai-api-key",
        CRITICAL,
        native=("openai-api-key", "openai-api-key-project"),
        rules=("openai-api-key",),
        detect_secrets=("OpenAI Token",),
        kingfisher=("openai",),
        rule_patterns=("openai-*",),
    ),
    CredentialClass(
        "anthropic-api-key",
        CRITICAL,
        native=("anthropic-api-key",),
        rules=("anthropic-api-key", "anthropic-admin-api-key"),
        kingfisher=("anthropic",),
        rule_patterns=("anthropic-*",),
    ),
    CredentialClass(
        "heroku-api-key",
        CRITICAL,
        native=("heroku-api-key",),
        rules=("heroku-api-key", "heroku-api-key-v2"),
        kingfisher=("heroku",),
        rule_patterns=("heroku-*",),
    ),
    CredentialClass(
        "mailchimp-api-key",
        CRITICAL,
        native=("mailchimp-api-key",),
        rules=("mailchimp-api-key",),
        detect_secrets=("Mailchimp Access Key",),
        kingfisher=("mailchimp",),
        rule_patterns=("mailchimp-*",),
    ),
    CredentialClass(
        "mailgun-api-key",
        CRITICAL,
        native=("mailgun-api-key",),
        rules=("mailgun-private-api-token",),
        kingfisher=("mailgun",),
        rule_patterns=("mailgun-*",),
    ),
    CredentialClass(
        "telegram-bot-token",
        CRITICAL,
        native=("telegram-bot-token",),
        rules=("telegram-bot-api-token",),
        detect_secrets=("Telegram Bot Token",),
        kingfisher=("telegram",),
        rule_patterns=("telegram-*",),
    ),
    CredentialClass(
        "discord-bot-token",
        CRITICAL,
        native=("discord-bot-token", "discord-webhook"),
        rules=("discord-api-token", "discord-client-secret"),
        detect_secrets=("Discord Bot Token",),
        kingfisher=("discord",),
        rule_patterns=("discord-*",),
    ),
    CredentialClass(
        "facebook-access-token",
        CRITICAL,
        native=("facebook-access-token",),
        rules=("facebook-access-token", "facebook-page-access-token", "facebook-secret"),
        kingfisher=("facebook",),
        rule_patterns=("facebook-*",),
    ),
    CredentialClass(
        "shopify-token",
        CRITICAL,
        native=("shopify-access-token", "shopify-shared-secret"),
        rules=(
            "shopify-access-token",
            "shopify-custom-access-token",
            "shopify-private-app-access-token",
            "shopify-shared-secret",
        ),
        kingfisher=("shopify",),
        rule_patterns=("shopify-*",),
    ),
    CredentialClass(
        "digitalocean-token",
        CRITICAL,
        native=("digitalocean-token", "digitalocean-oauth", "digitalocean-refresh"),
        rules=("digitalocean-pat", "digitalocean-access-token", "digitalocean-refresh-token"),
        kingfisher=("digitalocean",),
        rule_patterns=("digitalocean-*",),
    ),
    CredentialClass(
        "doppler-token",
        CRITICAL,
        native=("doppler-token",),
        rules=("doppler-api-token",),
        kingfisher=("doppler",),
        rule_patterns=("doppler-*",),
    ),
    CredentialClass(
        "postman-api-key",
        CRITICAL,
        native=("postman-api-key",),
        rules=("postman-api-token",),
        kingfisher=("postman",),
        rule_patterns=("postman-*",),
    ),
    CredentialClass(
        "linear-api-key",
        CRITICAL,
        native=("linear-api-key",),
        rules=("linear-api-key", "linear-client-secret"),
        kingfisher=("linear",),
        rule_patterns=("linear-*",),
    ),
    CredentialClass(
        "supabase-token",
        CRITICAL,
        native=("supabase-key",),
        rules=("supabase-management-token", "supabase-project-api-key"),
        kingfisher=("supabase",),
        rule_patterns=("supabase-*",),
    ),
    # --- HIGH
    CredentialClass(
        "twilio-sid",
        HIGH,
        native=("twilio-api-key", "twilio-account-sid", "twilio-app-sid"),
        rules=("twilio-api-key",),
        detect_secrets=("Twilio API Key",),
        kingfisher=("twilio",),
    ),
    CredentialClass(
        "generic-secret",
        HIGH,
        native=("generic-secret", "generic-api-key"),
        rules=("generic-api-key", "generic-password"),
        detect_secrets=("Secret Keyword",),
        kingfisher=(
            "api-key",
            "api_key",
            "apikey",
            "secret-key",
            "secret_key",
            "password",
            "token",
            "credential",
        ),
        git_secrets=("password", "token", "api-key"),
    ),
    CredentialClass(
        "credentials-in-url",
        HIGH,
        native=("database-url-postgres", "database-url-mysql", "database-url-mongodb", "redis-url"),
        rules=("generic-credential-uri", "mongodb-connection-string"),
        detect_secrets=("Basic Auth Credentials",),
        kingfisher=("mongodb", "jdbc"),
    ),
    CredentialClass(
        "artifactory-credentials",
        HIGH,
        rules=(
            "artifactory-api-key",
            "artifactory-reference-token",
            "jfrog-api-key",
            "jfrog-identity-token",
        ),
        detect_secrets=("Artifactory Credentials",),
    ),
    CredentialClass("docker-auth", HIGH, native=("docker-auth",), kingfisher=("docker",)),
    CredentialClass(
        "algolia-api-key", HIGH, native=("algolia-api-key",), rules=("algolia-api-key",)
    ),
    CredentialClass(
        "atlassian-api-token",
        HIGH,
        native=("atlassian-api-token",),
        rules=("atlassian-api-token",),
    ),
    CredentialClass(
        "cloudflare-api-token",
        HIGH,
        native=("cloudflare-api-token",),
        rules=("cloudflare-api-key",),
    ),
    CredentialClass(
        "datadog-api-key",
        HIGH,
        native=("datadog-api-key",),
        rules=("datadog-access-token", "datadog-api-key"),
    ),
    # A JWT is never graded below HIGH. Some are public by design (an OIDC ID token, a
    # Supabase anon key), but a bearer or session token and a Supabase service_role key have
    # the same shape, no rule can tell them apart, and gitleaks, Infisical and detect-secrets
    # always graded them HIGH. The native scanner used to say MEDIUM, which let a JWT through
    # the default gate whenever gitleaks was not there to catch it.
    CredentialClass(
        "jwt",
        HIGH,
        native=("jwt-token",),
        rules=("jwt", "jwt-base64"),
        detect_secrets=("JSON Web Token",),
    ),
    # Native patterns that no other scanner has a class for, pinned at the grade they have.
    CredentialClass("github-app-client-id", HIGH, native=("github-app-client-id",)),
    CredentialClass("recaptcha-secret", HIGH, native=("google-recaptcha-secret",)),
    CredentialClass("auth-header", HIGH, native=("basic-auth-header", "bearer-token-header")),
    CredentialClass("npmrc-credentials", HIGH, native=("npmrc-auth", "npmrc-authtoken")),
    CredentialClass(
        "framework-secret-key",
        HIGH,
        native=("laravel-app-key", "django-secret-key", "wordpress-auth-key"),
    ),
    CredentialClass(
        "config-password",
        HIGH,
        native=("php-db-password", "connection-string-password", "ftp-password", "xml-password"),
    ),
    CredentialClass("sentry-dsn", HIGH, native=("sentry-dsn",)),
    CredentialClass(
        "hosting-and-monitoring-token",
        HIGH,
        native=("vercel-token", "netlify-token", "newrelic-license-key"),
    ),
    # --- MEDIUM: entropy is a weak signal, and git-secrets cannot classify a line by a rule
    CredentialClass(
        "high-entropy-string",
        MEDIUM,
        native=("high-entropy-string",),
        detect_secrets=("Base64 High Entropy String", "Hex High Entropy String"),
    ),
    CredentialClass("base64-auth-token", MEDIUM, native=("base64-auth-token",)),
    CredentialClass("unclassified-match", MEDIUM, git_secrets=("generic-secret",)),
)

# Rules of a CRITICAL class's provider that are not a credential, so they stay HIGH. The
# real rule IDs of the tools are checked against the shared table: a rule whose provider is
# in a CRITICAL class (``CredentialClass.rule_patterns``) must be CRITICAL there, or be named
# here with the reason. A rule added by a tool upgrade that is neither fails the check.
WAIVED_RULES: dict[str, str] = {
    "azure-client-id": "an application ID, not a credential",
    "azure-tenant-id": "a directory ID, not a credential",
    "azure-storage-account-name": "an account name; the key is azure-storage-account-key",
    "discord-client-id": "an application ID, not a credential",
    "mailgun-pub-key": "a public validation key, public by design",
    "mailgun-signing-key": "a webhook signing key: it proves Mailgun's identity to you and "
    "cannot send mail",
    "supabase-project-url": "a project URL, not a credential",
}

# ``stripe-access-token`` matches test-mode keys too. They cannot move money and no other
# scanner flags them, so they are HIGH while a live key is CRITICAL (#844). Their sample
# file is in ``class_samples()`` under ``STRIPE_TEST_SAMPLE``, which no class owns.
STRIPE_TEST_KEY_SEVERITY = HIGH
STRIPE_TEST_SAMPLE = "stripe-test-key"


# --- Sample files -------------------------------------------------------------------------

_ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_LOWNUM = "abcdefghijklmnopqrstuvwxyz0123456789"
_HEX = "0123456789abcdef"
_DIGITS = "0123456789"
_UPNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_URL = _ALNUM + "_-"


def _tok(seed: str, length: int, alphabet: str = _ALNUM) -> str:
    """A deterministic random-looking token, so no credential literal appears in source."""
    out = ""
    counter = 0
    while len(out) < length:
        digest = hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        out += "".join(alphabet[byte % len(alphabet)] for byte in digest)
        counter += 1
    return out[:length]


def _pem(kind: str, seed: str) -> str:
    body = base64.b64encode(hashlib.sha512(seed.encode()).digest() * 6).decode()
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN " + kind + "-----\n" + "\n".join(lines) + "\n-----END " + kind + "-----\n"


def _jwt() -> str:
    head = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    claims = base64.urlsafe_b64encode(b'{"sub":"1234567890","name":"John Doe","iat":1516239022}')
    return head + "." + claims.decode().rstrip("=") + "." + _tok("jwt-sig", 43, _URL)


def class_samples() -> dict[str, dict[str, str]]:
    """One or more sample files per class: ``{class name: {file name: content}}``.

    Every value is built from a seeded stream, so these are realistic enough for the real
    scanners to flag, yet no complete secret appears in source (GitHub push protection).
    """
    s: dict[str, dict[str, str]] = {}
    s["aws"] = {
        "aws-key-id.env": "AWS_ACCESS_KEY_ID=AKIA" + _tok("aws1", 16, _UPNUM) + "\n",
        "aws-pair.env": (
            "AWS_ACCESS_KEY_ID=AKIA" + _tok("aws2", 16, _UPNUM) + "\n"
            "AWS_SECRET_ACCESS_KEY=" + _tok("aws2s", 40, _ALNUM + "/+") + "\n"
        ),
        "aws-bedrock.env": "AWS_BEARER_TOKEN_BEDROCK=ABSK" + _tok("aws3", 120) + "\n",
    }
    s["azure-storage-key"] = {
        "azure-storage.env": (
            "AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=probe"
            + _tok("az1", 6, _LOWNUM)
            + ";AccountKey="
            + base64.b64encode(hashlib.sha512(b"azkey").digest()).decode()
            + ";EndpointSuffix=core.windows.net\n"
        ),
        "azure-appconfig.env": (
            "AZURE_APPCONFIG_CONNECTION_STRING=Endpoint=https://probe"
            + _tok("az2", 6, _LOWNUM)
            + ".azconfig.io;Id="
            + _tok("az3", 20)
            + ";Secret="
            + _tok("az4", 44, _ALNUM + "+/")
            + "\n"
        ),
        "azure-servicebus.env": (
            "SERVICEBUS_CONNECTION_STRING=Endpoint=sb://probe"
            + _tok("az5", 6, _LOWNUM)
            + ".servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey"
            + ";SharedAccessKey="
            + _tok("az6", 44, _ALNUM + "+/")
            + "\n"
        ),
    }
    s["azure-ad-client-secret"] = {
        "azure-ad.env": (
            "AZURE_CLIENT_SECRET="
            + _tok("azad", 3)
            + "8Q~"
            + _tok("azad2", 34, _ALNUM + "_.-~")
            + "\n"
        )
    }
    s["gcp-service-account"] = {
        "service-account.json": (
            '{\n  "type": "service_account",\n  "project_id": "demo-'
            + _tok("gsa", 6, _LOWNUM)
            + '",\n  "private_key_id": "'
            + _tok("gsa2", 40, _HEX)
            + '",\n  "private_key": "-----BEGIN PRIVATE KEY-----\\n'
            + base64.b64encode(hashlib.sha512(b"gsa").digest() * 8).decode()
            + '\\n-----END PRIVATE KEY-----\\n",\n'
            '  "client_email": "svc@demo.iam.gserviceaccount.com"\n}\n'
        ),
        # Application Default Credentials: the user's refresh token and the app's client secret.
        "adc.json": (
            '{\n  "client_id": "'
            + _tok("adc1", 12, _DIGITS)
            + "-"
            + _tok("adc2", 32, _LOWNUM)
            + '.apps.googleusercontent.com",\n  "client_secret": "GOCSPX-'
            + _tok("adc3", 28, _URL)
            + '",\n  "refresh_token": "1//0'
            + _tok("adc4", 60, _URL)
            + '",\n  "type": "authorized_user"\n}\n'
        ),
    }
    s["google-api-key"] = {
        "google.env": "GOOGLE_API_KEY=AIza" + _tok("gapi", 35, _URL) + "\n",
        "gemini.env": "GEMINI_API_KEY=AQ.Ab8RN6" + _tok("gem", 44, _URL) + "\n",
    }
    s["ibm-cloud-iam-key"] = {"ibm.env": "IBM_CLOUD_API_KEY=" + _tok("ibm", 44, _URL) + "\n"}
    s["github-token"] = {
        "github-pat.env": "GITHUB_TOKEN=ghp_" + _tok("ghp", 36) + "\n",
        "github-oauth.env": "GH_OAUTH=gho_" + _tok("gho", 36) + "\n",
        "github-app.env": (
            "GH_APP=ghu_" + _tok("ghu", 36) + "\nGH_APP2=ghs_" + _tok("ghs", 36) + "\n"
        ),
        "github-refresh.env": "GH_REFRESH=ghr_" + _tok("ghr", 36) + "\n",
        "github-fine.env": "GH_FINE=github_pat_" + _tok("ghf", 22) + "_" + _tok("ghf2", 59) + "\n",
    }
    s["gitlab-token"] = {
        "gitlab-pat.env": "GITLAB_TOKEN=glpat-" + _tok("glpat", 20, _URL) + "\n",
        "gitlab-ptt.env": "GL_TRIGGER=glptt-" + _tok("glptt", 40, _HEX) + "\n",
        "gitlab-runner-auth.env": "GL_RUNNER=glrt-" + _tok("glrt", 20, _URL) + "\n",
        "gitlab-runner-reg.env": "GL_RUNNER_REG=GR1348941" + _tok("glgr", 20, _URL) + "\n",
        "gitlab-deploy.env": "GL_DEPLOY=gldt-" + _tok("gldt", 20, _URL) + "\n",
        "gitlab-feed.env": "GL_FEED=glft-" + _tok("glft", 20, _URL) + "\n",
        "gitlab-scim.env": "GL_SCIM=glsoat-" + _tok("glsoat", 20, _URL) + "\n",
        "gitlab-agent.env": "GL_AGENT=glagent-" + _tok("glagent", 50, _URL) + "\n",
        "gitlab-oauth.env": "GL_OAUTH=gloas-" + _tok("gloas", 64, _HEX) + "\n",
        "gitlab-mail.env": "GL_MAIL=glimt-" + _tok("glimt", 25, _URL) + "\n",
        "gitlab-job.env": "GL_JOB=glcbt-1f_" + _tok("glcbt", 20, _URL) + "\n",
        "gitlab-flag.env": "GL_FLAG=glffct-" + _tok("glffct", 20, _URL) + "\n",
        "gitlab-mail-address.env": (
            "REPLY_TO=incoming+demo-project-12345-"
            + _tok("glmail", 24, _URL)
            + "-issue@gitlab.example\n"
        ),
        "gitlab-session.env": "Cookie: _gitlab_session=" + _tok("glsess", 32, _LOWNUM) + "\n",
    }
    s["npm-token"] = {".npmrc": "//registry.npmjs.org/:_authToken=npm_" + _tok("npm", 36) + "\n"}
    s["pypi-token"] = {
        "pypi.env": "PYPI_TOKEN=pypi-AgEIcHlwaS5vcmc" + _tok("pypi", 90, _URL) + "\n"
    }
    s["vault-token"] = {
        "vault.env": (
            "VAULT_TOKEN=hvs."
            + _tok("vt1", 95, _URL)
            + "\nVAULT_BATCH=hvb."
            + _tok("vt2", 120, _URL)
            + "\n"
        )
    }
    s["private-key"] = {
        "rsa.pem": _pem("RSA PRIVATE KEY", "rsa"),
        "generic.pem": _pem("PRIVATE KEY", "gen"),
        "ec.pem": _pem("EC PRIVATE KEY", "ec"),
        "openssh.key": _pem("OPENSSH PRIVATE KEY", "ossh"),
        "pgp.asc": _pem("PGP PRIVATE KEY BLOCK", "pgp"),
        "age.key": "AGE-SECRET-KEY-1" + _tok("age", 58, "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L") + "\n",
        "wallet.env": "POLYMARKET_PRIVATE_KEY=0x" + _tok("poly", 64, _HEX) + "\n",
    }
    s["password-hash"] = {
        "bcrypt.txt": "hash=$2b$12$" + _tok("bc1", 53, "./" + _ALNUM) + "\n",
        "sha512crypt.txt": "hash=$6$"
        + _tok("sc1", 16, "./" + _ALNUM)
        + "$"
        + _tok("sc2", 86, "./" + _ALNUM)
        + "\n",
    }
    s["stripe-live-key"] = {
        "stripe-live.env": "STRIPE_KEY=sk_live_" + _tok("stl", 32) + "\n",
        "stripe-restricted.env": "STRIPE_RK=rk_live_" + _tok("strl", 32) + "\n",
    }
    s[STRIPE_TEST_SAMPLE] = {"stripe-test.env": "STRIPE_TEST_KEY=sk_test_" + _tok("stt", 32) + "\n"}
    s["square-token"] = {
        "square.env": (
            "SQUARE_TOKEN=sq0atp-"
            + _tok("sq1", 22, _URL)
            + "\nSQUARE_SECRET=sq0csp-"
            + _tok("sq2", 43, _URL)
            + "\n"
        )
    }
    s["slack-token"] = {
        "slack-bot.env": (
            "SLACK_BOT=xoxb-"
            + _tok("sb1", 11, _DIGITS)
            + "-"
            + _tok("sb2", 11, _DIGITS)
            + "-"
            + _tok("sb3", 24)
            + "\n"
        ),
        "slack-user.env": (
            "SLACK_USER=xoxp-"
            + _tok("su1", 11, _DIGITS)
            + "-"
            + _tok("su2", 11, _DIGITS)
            + "-"
            + _tok("su3", 11, _DIGITS)
            + "-"
            + _tok("su4", 32, _HEX)
            + "\n"
        ),
        "slack-app.env": (
            "SLACK_APP=xapp-1-A"
            + _tok("sa1", 10, _DIGITS)
            + "-"
            + _tok("sa2", 13, _DIGITS)
            + "-"
            + _tok("sa3", 64, _HEX)
            + "\n"
        ),
        "slack-config.env": (
            "SLACK_CFG=xoxe.xoxp-1-"
            + _tok("sc1", 160)
            + "\nSLACK_CFG_REFRESH=xoxe-1-"
            + _tok("sc2", 150)
            + "\n"
        ),
        "slack-legacy.env": (
            "SLACK_LEGACY=xoxs-"
            + _tok("sl1", 11, _DIGITS)
            + "-"
            + _tok("sl2", 11, _DIGITS)
            + "-"
            + _tok("sl3", 11, _DIGITS)
            + "-"
            + _tok("sl4", 32, _HEX)
            + "\nSLACK_WS=xoxa-2-"
            + _tok("sl5", 11, _DIGITS)
            + "-"
            + _tok("sl6", 11, _DIGITS)
            + "-"
            + _tok("sl7", 11, _DIGITS)
            + "-"
            + _tok("sl8", 32, _HEX)
            + "\n"
        ),
        "slack-webhook.env": (
            "SLACK_WEBHOOK=https://hooks.slack.com/services/T"
            + _tok("sw1", 8, _UPNUM)
            + "/B"
            + _tok("sw2", 10, _UPNUM)
            + "/"
            + _tok("sw3", 24)
            + "\n"
        ),
    }
    s["sendgrid-api-key"] = {
        "sendgrid.env": (
            "SENDGRID_API_KEY=SG." + _tok("sg1", 22, _URL) + "." + _tok("sg2", 43, _URL) + "\n"
        )
    }
    s["openai-api-key"] = {
        "openai.env": "OPENAI_API_KEY=sk-" + _tok("oai1", 20) + "T3BlbkFJ" + _tok("oai2", 20) + "\n"
    }
    s["anthropic-api-key"] = {
        "anthropic.env": "ANTHROPIC_API_KEY=sk-ant-api03-" + _tok("ant", 93, _URL) + "AA\n"
    }
    s["heroku-api-key"] = {
        "heroku.env": (
            "HEROKU_API_KEY="
            + _tok("hk1", 8, _HEX)
            + "-"
            + _tok("hk2", 4, _HEX)
            + "-"
            + _tok("hk3", 4, _HEX)
            + "-"
            + _tok("hk4", 4, _HEX)
            + "-"
            + _tok("hk5", 12, _HEX)
            + "\n"
        ),
        "heroku-v2.env": "HEROKU_KEY=HRKU-AA" + _tok("hk6", 58, _URL) + "\n",
    }
    s["mailchimp-api-key"] = {
        "mailchimp.env": "MAILCHIMP_API_KEY=" + _tok("mc", 32, _HEX) + "-us20\n"
    }
    s["mailgun-api-key"] = {"mailgun.env": "MAILGUN_API_KEY=key-" + _tok("mg1", 32, _HEX) + "\n"}
    s["telegram-bot-token"] = {
        "telegram.env": (
            "TELEGRAM_BOT_TOKEN=" + _tok("tg1", 9, _DIGITS) + ":A" + _tok("tg2", 34, _URL) + "\n"
        )
    }
    s["discord-bot-token"] = {
        "discord.env": (
            "DISCORD_TOKEN=M"
            + _tok("dc1", 23)
            + "."
            + _tok("dc2", 6, _URL)
            + "."
            + _tok("dc3", 27, _URL)
            + "\n"
        ),
        "discord-api.env": "DISCORD_API_TOKEN=" + _tok("dc4", 64, _HEX) + "\n",
        "discord-client.env": "DISCORD_CLIENT_SECRET=" + _tok("dc5", 32, _LOWNUM) + "\n",
    }
    s["facebook-access-token"] = {
        "facebook.env": "FB_PAGE_TOKEN=EAAM" + _tok("fb1", 120) + "\n",
        "facebook-secret.env": "FACEBOOK_APP_SECRET=" + _tok("fb2", 32, _HEX) + "\n",
    }
    s["shopify-token"] = {
        "shopify.env": (
            "SHOPIFY_TOKEN=shpat_"
            + _tok("sh1", 32, _HEX)
            + "\nSHOPIFY_SECRET=shpss_"
            + _tok("sh2", 32, _HEX)
            + "\n"
        )
    }
    s["digitalocean-token"] = {
        "digitalocean.env": (
            "DO_TOKEN=dop_v1_"
            + _tok("do1", 64, _HEX)
            + "\nDO_OAUTH=doo_v1_"
            + _tok("do2", 64, _HEX)
            + "\nDO_REFRESH=dor_v1_"
            + _tok("do3", 64, _HEX)
            + "\n"
        )
    }
    s["doppler-token"] = {
        # gitleaks matches personal tokens (dp.pt.), the native scanner CLI/service ones.
        "doppler.env": (
            "DOPPLER_TOKEN=dp.pt."
            + _tok("dp1", 43)
            + "\nDOPPLER_SERVICE_TOKEN=dp.st."
            + _tok("dp2", 44)
            + "\n"
        )
    }
    s["postman-api-key"] = {
        "postman.env": "POSTMAN_KEY=PMAK-"
        + _tok("pm1", 24, _HEX)
        + "-"
        + _tok("pm2", 34, _HEX)
        + "\n"
    }
    s["linear-api-key"] = {
        "linear.env": "LINEAR_KEY=lin_api_" + _tok("ln1", 40) + "\n",
        "linear-secret.env": "LINEAR_CLIENT_SECRET=" + _tok("ln2", 32, _HEX) + "\n",
    }
    s["supabase-token"] = {
        "supabase.env": "SUPABASE_TOKEN=sbp_" + _tok("sp1", 40, _HEX) + "\n",
        # betterleaks reports the key only next to the project URL it is used with.
        "supabase-secret.env": (
            "SUPABASE_URL=https://"
            + _tok("sp3", 20, _LOWNUM)
            + ".supabase.co\nSUPABASE_SECRET_KEY=sb_secret_"
            + _tok("sp2", 31, _URL)
            + "\n"
        ),
    }
    s["twilio-sid"] = {
        "twilio.env": (
            "TWILIO_API_KEY=SK"
            + _tok("tw1", 32, _HEX)
            + "\nTWILIO_ACCOUNT_SID=AC"
            + _tok("tw2", 32, _HEX)
            + "\n"
        ),
        # Not a credential at all, but detect-secrets reports it as a Twilio API key.
        "cache-key.env": "CACHE_KEY=AC" + _tok("twc", 32, _HEX) + "\n",
    }
    s["generic-secret"] = {
        "generic-api.env": 'api_key = "' + _tok("ga1", 32) + '"\n',
        "generic-password.py": 'password = "' + _tok("gs1", 14) + '"\n',
    }
    s["credentials-in-url"] = {
        "basic-auth.txt": "url = https://deploy:"
        + _tok("ba1", 16)
        + "@repo.internal.example.com/x\n",
        "database-url.env": (
            "DATABASE_URL=postgres://app:" + _tok("db1", 16) + "@db.internal.example.com/prod\n"
        ),
        "mongodb.env": (
            "MONGO_URL=mongodb+srv://app:"
            + _tok("mo1", 16)
            + "@cluster0.example.mongodb.net/prod\n"
        ),
    }
    s["artifactory-credentials"] = {
        "artifactory.env": "ARTIFACTORY_KEY=AKCp" + _tok("af1", 69) + "\n"
    }
    s["algolia-api-key"] = {"algolia.env": "ALGOLIA_API_KEY=" + _tok("al1", 32, _HEX) + "\n"}
    s["atlassian-api-token"] = {
        "atlassian.env": "ATLASSIAN_API_TOKEN=" + _tok("at1", 20) + _tok("at2", 4, _HEX) + "\n"
    }
    s["cloudflare-api-token"] = {
        "cloudflare.env": "CLOUDFLARE_API_TOKEN=" + _tok("cf1", 40, _URL) + "\n"
    }
    s["datadog-api-key"] = {"datadog.env": "DATADOG_API_KEY=" + _tok("dd1", 40, _HEX) + "\n"}
    s["jwt"] = {"session.env": "SESSION=" + _jwt() + "\n"}
    return s
