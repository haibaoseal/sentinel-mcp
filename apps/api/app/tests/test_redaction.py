"""Redaction tests.

The predecessor's redaction test probed only the four shapes its own regexes
already covered, so it could never discover a gap -- it was a test that tested
the mock. These tests are written the other way round: every case is a shape the
*old* implementation leaked, and assertions check for the absence of a
discriminating substring rather than the presence of a marker.

The ``Bearer abc+/def==`` case is the reason for that rule: the old code
produced ``[REDACTED]+/def==``, which reads as redacted while leaking the tail.
"""

from __future__ import annotations

import pytest
from app.security.secrets import (
    MASK,
    is_sensitive_key,
    mask_credential,
    normalise_key,
    redact_text,
    sanitize_payload,
)

# (label, secret, must-not-survive substring)
#
# The Slack fixtures are assembled from parts rather than written as single
# literals. A string in credential shape trips host-side secret scanners -- GitHub
# push protection refuses the push -- and a redaction fixture is not worth an
# allow-list entry. The redactor still receives the whole token at run time.
CREDENTIAL_CASES = [
    ("openai lowercase", "sk-abc123XYZdef456ghi789", "abc123XYZdef456ghi789"),
    ("openai uppercase", "SK-abc123XYZdef456ghi789", "abc123XYZdef456ghi789"),
    ("openai mixed case", "Sk-Abc123XYZdef456ghi789", "Abc123XYZdef456ghi789"),
    ("github pat", "ghp_abcdefghijklmnopqrstuvwx", "abcdefghijklmnopqrstuvwx"),
    ("github fine-grained", "github_pat_" + "A" * 30, "A" * 30),
    ("slack bot", "xoxb-" + "123456789012" + "-" + "abcdefghijklmnop", "abcdefghijklmnop"),
    ("slack user", "xoxp-" + "987654321098" + "-" + "zyxwvutsrqponmlk", "zyxwvutsrqponmlk"),
    (
        "google api key",
        "AIzaSyA1B2C3D4E5F6G7H8I9J0KLMNOPQRSTUV",
        "A1B2C3D4E5F6G7H8I9J0KLMNOPQRSTUV",
    ),
    ("aws access key", "AKIAIOSFODNN7EXAMPLE", "IOSFODNN7EXAMPLE"),
    ("azure style 32 hex", "a1b2c3d4e5f60718293a4b5c6d7e8f90", "a1b2c3d4e5f60718293a4b5c6d7e8f90"),
    ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnopqrst", "eyJzdWIiOiIxIn0"),
    (
        "private key body",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
        "MIIEowIBAAKCAQEA",
    ),
    ("bearer with base64 tail", "Bearer abc+/def==", "+/def=="),
    ("basic auth", "Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="),
    ("postgres dsn", "postgresql://user:S3cretPass@db.internal:5432/prod", "S3cretPass"),
]

PII_CASES = [
    ("cn national id", "110101199003071234", "110101199003071234"),
    ("cn national id X", "11010119900307123X", "11010119900307123X"),
    ("cn mobile", "13800138000", "13800138000"),
    ("cn mobile spaced", "138 0013 8000", "0013 8000"),
    ("cn mobile dashed", "138-0013-8000", "0013-8000"),
    ("cn landline", "010-12345678", "12345678"),
    ("email", "someone@example.com", "someone@example.com"),
]


@pytest.mark.parametrize(
    "label,secret,leak", CREDENTIAL_CASES, ids=[c[0] for c in CREDENTIAL_CASES]
)
def test_credential_shapes_do_not_survive(label, secret, leak):
    redacted = redact_text(f"value is {secret} end")
    assert leak not in redacted, f"{label}: {leak!r} leaked through redaction -> {redacted!r}"


@pytest.mark.parametrize("label,secret,leak", PII_CASES, ids=[c[0] for c in PII_CASES])
def test_pii_shapes_do_not_survive(label, secret, leak):
    redacted = redact_text(f"contact {secret} end")
    assert leak not in redacted, f"{label}: {leak!r} leaked -> {redacted!r}"


def test_bearer_redaction_is_not_merely_cosmetic():
    """Guards the worst failure mode: a partial mask that leaks the tail."""
    redacted = redact_text("Authorization: Bearer abc+/def==")
    assert "def" not in redacted.replace("Bearer", "")
    assert MASK in redacted


@pytest.mark.parametrize(
    "key",
    [
        "apiKey",
        "api_key",
        "API_KEY",
        "x-api-key",
        "OPENAI_API_KEY",
        "token",
        "accessToken",
        "sessionToken",
        "secretToken",
        "password",
        "passwd",
        "clientSecret",
        "private_key",
        "privateKey",
        "credential",
        "credentials",
        "authorization",
        "cookie",
        "email",
        "emails",
        "phone",
        "phones",
        "mobile",
        "shippingAddress",
        "address",
        "customerName",
        "customer_name",
        "userName",
        "realName",
        "session_id",
    ],
)
def test_sensitive_key_names_are_recognised(key):
    assert is_sensitive_key(key), f"{key!r} should be treated as sensitive"


@pytest.mark.parametrize(
    "key", ["tokenBudget", "tokenUsage", "tokenizer", "mailbox", "created_at", "task_id", "status"]
)
def test_non_sensitive_keys_are_not_over_redacted(key):
    """Over-redaction destroys the audit trail's usefulness, so it is a bug too."""
    assert not is_sensitive_key(key), f"{key!r} should not be treated as sensitive"


def test_key_normalisation_collapses_separators():
    assert normalise_key("X_API-KEY") == "xapikey"
    assert normalise_key(" apiKey ") == "apikey"


def test_non_string_values_under_sensitive_keys_are_masked():
    """A phone number stored as an int is still a phone number."""
    assert sanitize_payload({"phones": [13800138000]}) == {"phones": [MASK]}
    assert sanitize_payload({"phone": 13800138000}) == {"phone": MASK}
    assert sanitize_payload({"customerName": {"first": "张伟"}}) == {
        "customerName": {"first": MASK}
    }


def test_nested_sensitive_context_propagates():
    payload = {"auth": {"headers": {"x": "Bearer abcdefghijklmnop"}}}
    sanitized = sanitize_payload(payload)
    assert "abcdefghijklmnop" not in str(sanitized)


def test_redaction_is_idempotent():
    """Running twice must not corrupt an already-masked value."""
    once = redact_text("token ghp_abcdefghijklmnopqrstuvwx")
    twice = redact_text(once)
    assert once == twice


def test_mask_credential_does_not_reveal_the_body():
    masked = mask_credential("ghp_abcdefghijklmnopqrstuvwx")
    assert "abcdefghijklmno" not in masked
    assert MASK in masked


def test_ordinary_text_is_left_alone():
    """Audit payloads must stay readable; redaction must not eat normal content."""
    text = "Task created for user u-123 with title 'Quarterly report' at 2026-01-01T00:00:00Z"
    assert redact_text(text) == text


# --- after the second audit: the evidence the redactor was destroying ---------


def test_a_git_sha_survives_redaction():
    """40 hex is a commit id. The 32-64 range ate every one of them."""
    sha = "5fac9b1e7d3c2a4b6f8e0d1c3b5a7f9e2d4c6b8a"

    assert sha in redact_text(f"commit {sha} done")


def test_an_author_is_not_a_credential():
    """`auth` as a substring marker masked every GitHub author in an audit payload."""
    assert sanitize_payload({"author": "octocat"}) == {"author": "octocat"}
    assert sanitize_payload({"auth_token": "abc123"}) == {"auth_token": MASK}
    assert is_sensitive_key("sessionCount") is False
    assert is_sensitive_key("sessionId") is True


def test_a_payment_card_is_masked_and_a_plain_number_is_not():
    """Luhn is the difference between a card and a 16-digit order id."""
    assert "4111 1111 1111 1111" not in redact_text("card 4111 1111 1111 1111")
    assert "1234567890123456" in redact_text("order 1234567890123456")


def test_shapes_the_first_pass_did_not_know_are_recognised():
    # The Stripe and Hugging Face fixtures are assembled from parts, for the same
    # reason as the Slack one above: a literal in credential shape is refused by
    # GitHub push protection, and a test fixture is not worth an allow-list entry.
    for text, marker in [
        ("ssn 123-45-6789", "123-45-6789"),
        ("iban DE89370400440532013000", "DE89370400440532013000"),
        ("key sk_" + "live_51H8xQ2eZvKYlo2Cabcdefgh", "51H8xQ2eZvKYlo2Cabcdefgh"),
        ("token hf_" + "abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
    ]:
        assert marker not in redact_text(text), text
