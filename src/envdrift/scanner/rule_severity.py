"""Severity for the scanners that report gitleaks rule IDs: gitleaks and Infisical.

Neither tool reports a severity, so envdrift grades each finding by the rule that matched.
The two share this one table because they share one rule set: the default rules of
Infisical 0.43.135 are gitleaks', and Infisical 0.43.136 and later (the betterleaks engine)
report a superset of them under the same IDs. The keys are rule IDs read from real reports
of gitleaks 8.30.1 and of both Infisical engines.

Kingfisher's main catalog is betterleaks' too (its rule IDs are ``betterleaks.<id>``), so it
grades those rules through this table as well.

The grades are one slice of a severity policy: a credential class gets the same severity
from the native scanner, gitleaks, Infisical, detect-secrets, Kingfisher and git-secrets,
and the native scanner's grade is the reference (see "Severity" in docs/cli/guard.md).
``tests/severity_policy.py`` encodes the policy once, and a test fails when any of those
scanners' tables drifts from it. A rule that is not listed here is HIGH, the grade of the
generic rules. Every rule of a provider in a CRITICAL class is listed here, or is waived in
``tests/severity_policy.py`` because it matches an identifier or a public value. A test
checks that against the rule IDs of the tools as tested (``tests/fixtures/scanner_rule_ids.json``:
the rules embedded in the gitleaks and Infisical binaries, and Kingfisher's published list).
When a pinned tool is upgraded, extract them again, and the test names each new rule of such
a provider that this table does not grade.
"""

from __future__ import annotations

import re

from envdrift.scanner.base import FindingSeverity

RULE_SEVERITY_MAP: dict[str, FindingSeverity] = {
    # AWS. Both engines report access key IDs (AKIA, ASIA, ...) under ``aws-access-token``.
    # From Infisical 0.43.136 that happens only next to a secret access key, which betterleaks
    # nests as ``aws-secret-access-key``. Upstream betterleaks#410 makes that secret optional,
    # which brings lone key IDs back under ``aws-access-token``. Infisical 0.43.135 has no
    # secret access key rule, and every version reports a lone secret access key only as
    # ``generic-api-key`` (HIGH).
    "aws-access-token": FindingSeverity.CRITICAL,
    "aws-secret-access-key": FindingSeverity.CRITICAL,
    # Amazon Bedrock API keys are bearer credentials (gitleaks 8.30.1 and betterleaks), and
    # ``aws-session-token`` is a betterleaks rule that Kingfisher embeds.
    "aws-amazon-bedrock-api-key-long-lived": FindingSeverity.CRITICAL,
    "aws-amazon-bedrock-api-key-short-lived": FindingSeverity.CRITICAL,
    "aws-session-token": FindingSeverity.CRITICAL,
    # Other cloud credentials. Only betterleaks has ``azure-storage-account-key``,
    # ``gcp-service-account`` and ``ibm-cloud-user-api-key``: Infisical 0.43.135 reports an
    # Azure storage key as ``generic-api-key`` (HIGH). A GCP service-account match always spans
    # the account's private key, which the ``private-key`` rule of both engines also reports.
    # The Azure connection strings carry their shared key or secret, so they are credentials.
    # The rules for an Azure client, tenant or storage account ID are not: they stay HIGH.
    "azure-storage-account-key": FindingSeverity.CRITICAL,
    "azure-ad-client-secret": FindingSeverity.CRITICAL,
    "azure-app-configuration-connection-string": FindingSeverity.CRITICAL,
    "azure-servicebus-connection-string": FindingSeverity.CRITICAL,
    "gcp-service-account": FindingSeverity.CRITICAL,
    "gcp-application-default-credentials": FindingSeverity.CRITICAL,
    "gcp-api-key": FindingSeverity.CRITICAL,
    "gcp-gemini-api": FindingSeverity.CRITICAL,
    "ibm-cloud-user-api-key": FindingSeverity.CRITICAL,
    # Source control and package registries.
    "github-app-token": FindingSeverity.CRITICAL,
    "github-fine-grained-pat": FindingSeverity.CRITICAL,
    "github-oauth": FindingSeverity.CRITICAL,
    "github-pat": FindingSeverity.CRITICAL,
    "github-refresh-token": FindingSeverity.CRITICAL,
    "gitlab-cicd-job-token": FindingSeverity.CRITICAL,
    "gitlab-deploy-token": FindingSeverity.CRITICAL,
    "gitlab-feature-flag-client-token": FindingSeverity.CRITICAL,
    "gitlab-feed-token": FindingSeverity.CRITICAL,
    "gitlab-incoming-mail-address-token": FindingSeverity.CRITICAL,
    "gitlab-incoming-mail-token": FindingSeverity.CRITICAL,
    "gitlab-kubernetes-agent-token": FindingSeverity.CRITICAL,
    "gitlab-oauth-app-secret": FindingSeverity.CRITICAL,
    "gitlab-pat": FindingSeverity.CRITICAL,
    "gitlab-pat-routable": FindingSeverity.CRITICAL,
    "gitlab-pat-routable-versioned": FindingSeverity.CRITICAL,
    "gitlab-ptt": FindingSeverity.CRITICAL,
    "gitlab-rrt": FindingSeverity.CRITICAL,
    "gitlab-runner-authentication-token": FindingSeverity.CRITICAL,
    "gitlab-runner-authentication-token-routable": FindingSeverity.CRITICAL,
    "gitlab-scim-token": FindingSeverity.CRITICAL,
    "gitlab-session-cookie": FindingSeverity.CRITICAL,
    "npm-access-token": FindingSeverity.CRITICAL,
    "pypi-upload-token": FindingSeverity.CRITICAL,
    "vault-batch-token": FindingSeverity.CRITICAL,
    "vault-service-token": FindingSeverity.CRITICAL,
    # Any ``-----BEGIN ... PRIVATE KEY-----`` block: PEM, OpenSSH or PGP. An age identity and a
    # Polymarket wallet key are private keys in other encodings.
    "private-key": FindingSeverity.CRITICAL,
    "age-secret-key": FindingSeverity.CRITICAL,
    "polymarket-private-key": FindingSeverity.CRITICAL,
    # Payments. ``stripe-access-token`` also matches test-mode keys; see ``rule_severity``.
    "square-access-token": FindingSeverity.CRITICAL,
    "stripe-access-token": FindingSeverity.CRITICAL,
    # Messaging and chat. The Slack session rules are betterleaks-only.
    "slack-app-token": FindingSeverity.CRITICAL,
    "slack-bot-token": FindingSeverity.CRITICAL,
    "slack-config-access-token": FindingSeverity.CRITICAL,
    "slack-config-refresh-token": FindingSeverity.CRITICAL,
    "slack-legacy-bot-token": FindingSeverity.CRITICAL,
    "slack-legacy-token": FindingSeverity.CRITICAL,
    "slack-legacy-workspace-token": FindingSeverity.CRITICAL,
    "slack-session-cookie": FindingSeverity.CRITICAL,
    "slack-session-token": FindingSeverity.CRITICAL,
    "slack-user-token": FindingSeverity.CRITICAL,
    "slack-webhook-url": FindingSeverity.CRITICAL,
    "telegram-bot-api-token": FindingSeverity.CRITICAL,
    # The Discord rules for a bot token and a client secret. A client ID is an identifier: HIGH.
    "discord-api-token": FindingSeverity.CRITICAL,
    "discord-client-secret": FindingSeverity.CRITICAL,
    # AI and SaaS API keys.
    "anthropic-admin-api-key": FindingSeverity.CRITICAL,
    "anthropic-api-key": FindingSeverity.CRITICAL,
    "digitalocean-access-token": FindingSeverity.CRITICAL,
    "digitalocean-pat": FindingSeverity.CRITICAL,
    "digitalocean-refresh-token": FindingSeverity.CRITICAL,
    "doppler-api-token": FindingSeverity.CRITICAL,
    "facebook-access-token": FindingSeverity.CRITICAL,
    "facebook-page-access-token": FindingSeverity.CRITICAL,
    "facebook-secret": FindingSeverity.CRITICAL,
    "heroku-api-key": FindingSeverity.CRITICAL,
    "heroku-api-key-v2": FindingSeverity.CRITICAL,
    "linear-api-key": FindingSeverity.CRITICAL,
    "linear-client-secret": FindingSeverity.CRITICAL,
    "mailchimp-api-key": FindingSeverity.CRITICAL,
    "mailgun-private-api-token": FindingSeverity.CRITICAL,
    "openai-api-key": FindingSeverity.CRITICAL,
    "postman-api-token": FindingSeverity.CRITICAL,
    "sendgrid-api-token": FindingSeverity.CRITICAL,
    "shopify-access-token": FindingSeverity.CRITICAL,
    "shopify-custom-access-token": FindingSeverity.CRITICAL,
    "shopify-private-app-access-token": FindingSeverity.CRITICAL,
    "shopify-shared-secret": FindingSeverity.CRITICAL,
    "supabase-management-token": FindingSeverity.CRITICAL,
    # ``sb_secret_`` keys. The project URL rule is an identifier and the anon key is public.
    "supabase-project-api-key": FindingSeverity.CRITICAL,
    # The original keys. No built-in rule uses them, but a custom rules config may.
    "aws-access-key-id": FindingSeverity.CRITICAL,
    "google-api-key": FindingSeverity.CRITICAL,
    "slack-token": FindingSeverity.CRITICAL,
    "stripe-api-key": FindingSeverity.CRITICAL,
    # These match the HIGH fallback and are listed only to make the choice explicit. The
    # generic rules match any assigned key or password. The Twilio rule matches an API key
    # SID, an identifier whose secret is a separate value. A JWT is HIGH, as it always was in
    # gitleaks and Infisical: some are public by design (an OIDC ID token, a Supabase anon
    # key), but a bearer or session token and a Supabase ``service_role`` key have the same
    # shape and no rule can tell them apart, so a JWT is never graded below HIGH.
    "jwt": FindingSeverity.HIGH,
    "jwt-base64": FindingSeverity.HIGH,
    "generic-api-key": FindingSeverity.HIGH,
    "generic-password": FindingSeverity.HIGH,
    "twilio-api-key": FindingSeverity.HIGH,
    "artifactory-api-key": FindingSeverity.HIGH,
    "artifactory-reference-token": FindingSeverity.HIGH,
    "jfrog-api-key": FindingSeverity.HIGH,
    "jfrog-identity-token": FindingSeverity.HIGH,
}

# ``stripe-access-token`` also matches test-mode keys (``sk_test_``, ``rk_test_``), which
# cannot move money. The native and detect-secrets scanners flag only live keys, so a
# test-mode key stays HIGH instead of the CRITICAL of a live one (#844).
_STRIPE_TEST_KEY_RE = re.compile(r"[rs]k_test_")


def rule_severity(rule_id: str, secret: str) -> FindingSeverity:
    """The severity of a finding under ``rule_id`` whose matched value is ``secret``."""
    rule = rule_id.lower()
    if rule == "stripe-access-token" and _STRIPE_TEST_KEY_RE.match(secret):
        return FindingSeverity.HIGH
    return RULE_SEVERITY_MAP.get(rule, FindingSeverity.HIGH)
