"""Secret and PII redaction.

Why this file is more careful than it looks
-------------------------------------------
The predecessor redacted with five Latin-only patterns and an *anchored* key
list. Measured against the real persistence path it let through an Azure-style
32-hex secret, an uppercase ``SK-`` token, ``ghp_``/``xoxb_`` tokens, Chinese
national ID numbers, landline and space-separated phone numbers, and every
sensitive key that was not spelled exactly ``apiKey``/``password``/``email``.

Worse, ``Bearer abc+/def==`` became ``[REDACTED]+/def==`` -- it *looked*
redacted while leaking the tail. A redactor that produces false confidence is
more dangerous than no redactor, so the tests for this module assert the
absence of discriminating *substrings*, not the presence of a marker.

Design rules
------------
1. Matching is case-insensitive and shape-based, never anchored to one spelling.
2. Key matching normalises separators, so ``x-api-key``, ``X_API_KEY`` and
   ``apiKey`` are one key, and matches suffixes/plurals so ``OPENAI_API_KEY``
   and ``emails`` are covered.
3. Non-string scalars a sensitive key may hold are replaced outright -- a phone
   number stored as an int is still a phone number.
4. Redaction is applied to the whole payload at the single persistence boundary,
   and also to any text that leaves the process (replay Markdown, eval report).
"""

from __future__ import annotations

import re
from typing import Any

MASK = "********"

# --- credential shapes -------------------------------------------------------
# Ordered longest-prefix-first where patterns could overlap.
CREDENTIAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # GitHub: ghp_, gho_, ghu_, ghs_, ghr_, github_pat_
    (
        "github_token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    ),
    # Slack: xoxb-, xoxp-, xoxa-, xoxr-, xoxs-
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    # Google API key. Real keys are `AIza` + 35 chars, but be tolerant of shorter
    # test-shaped values so a truncated key is still masked rather than missed.
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}\b")),
    # AWS access key id
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    # OpenAI / generic sk- keys. Case-insensitive, and long enough that the
    # matched span always ends inside the secret rather than at a delimiter.
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b", re.IGNORECASE)),
    # JWT: three base64url segments
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ),
    # PEM private key bodies and headers
    (
        "private_key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    ),
    ("private_key_header", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    # Bearer / Basic: consume the full credential alphabet including + / = so the
    # tail cannot survive.
    (
        "authorization",
        re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=\-]{8,}", re.IGNORECASE),
    ),
    # DSN with inline password
    (
        "dsn",
        re.compile(r"\b([a-z][a-z0-9+.\-]*://)[^\s:/@]+:[^\s:/@]+@", re.IGNORECASE),
    ),
    # Long opaque hex blobs (Azure-style keys, SHA-256 digests). 32 and 64 only:
    # 40 hex is a git SHA-1, and a redactor that eats every commit id in an audit
    # payload destroys evidence to protect nothing. A 40-character secret has to be
    # caught by its key name instead, which is stated in the README limitations.
    (
        "hex_secret",
        re.compile(r"(?<![0-9A-Za-z])(?:[0-9a-f]{32}|[0-9a-f]{64})(?![0-9A-Za-z])", re.IGNORECASE),
    ),
    # Stripe and Hugging Face keys, both measured leaking before this.
    ("stripe_key", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{20,}\b")),
)

# --- PII shapes --------------------------------------------------------------
PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Chinese resident ID: 18 digits with a valid-shaped birth date, or 15 digits.
    (
        "cn_national_id",
        re.compile(
            r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)"
        ),
    ),
    ("cn_national_id_15", re.compile(r"(?<!\d)[1-9]\d{14}(?!\d)")),
    # Mainland mobile, tolerating spaces/dashes between groups.
    ("cn_mobile", re.compile(r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d[-\s]?\d{4}[-\s]?\d{4}(?!\d)")),
    # Landline with area code.
    ("cn_landline", re.compile(r"(?<!\d)0\d{2,3}[-\s]?\d{7,8}(?!\d)")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    # Payment cards, spaces or dashes allowed between groups. Validated with Luhn
    # before masking: a 16-digit order id is not a card, and masking one would be the
    # same evidence-destroying mistake as the hex range above.
    ("payment_card", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")),
    ("us_ssn", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
)

ALL_PATTERNS = CREDENTIAL_PATTERNS + PII_PATTERNS

# --- sensitive keys ----------------------------------------------------------
# Substring markers, matched against a normalised key (lowercased, separators
# collapsed). Substring (not equality) so OPENAI_API_KEY and x-api-key are both
# covered by "api_key"/"apikey" once separators are normalised away.
_SENSITIVE_KEY_MARKERS: tuple[str, ...] = (
    "apikey",
    "token",
    "secret",
    "password",
    "passwd",
    "authorization",
    "cookie",
    "credential",
    "privatekey",
    "accesskey",
    "sessionkey",
    # `session` covers session_id / sessionId / sessionToken -- and, because matching
    # is by substring, `sessionCount` as well, which `_KEY_ALLOWLIST` below is what
    # actually excludes. A broad marker list needs its false-positive cases written
    # down and tested, not asserted in a comment.
    "session",
    "dsn",
    "bearer",
    "email",
    "phone",
    "mobile",
    "address",
    "fullname",
    "realname",
    "customername",
    "username",
    "contact",
)

# Markers that must match a whole separator-delimited part of the key.
#
# "auth" is the reason this list exists. As a substring marker it matched `author`,
# so every GitHub author in an audit payload was masked as a secret -- a redactor
# that destroys the evidence it is supposed to protect. `authorization` is still
# caught by the substring list above, and `auth_token` matches here.
_KEY_WORD_MARKERS: tuple[str, ...] = ("auth",)

# Canonical spellings that must NOT be treated as sensitive even though they
# contain a marker. Kept explicit so the list above can stay broad.
_KEY_ALLOWLIST: frozenset[str] = frozenset(
    {
        "tokenbudget",
        "tokenusage",
        "tokenizer",
        "secretscannerfindings",
        "passwordpolicy",
        "sessioncount",
        "sessioncounts",
    }
)

_SEPARATOR_RE = re.compile(r"[\s._\-]+")


def normalise_key(key: str) -> str:
    return _SEPARATOR_RE.sub("", key.strip().lower())


def is_sensitive_key(key: str) -> bool:
    normalised = normalise_key(key)
    if not normalised or normalised in _KEY_ALLOWLIST:
        return False
    if normalised.endswith("mailbox"):  # not a person's email
        return False
    if any(marker in normalised for marker in _SENSITIVE_KEY_MARKERS):
        return True
    parts = [part.lower() for part in _SEPARATOR_RE.split(key.strip()) if part]
    return any(part in _KEY_WORD_MARKERS for part in parts)


def mask_credential(value: str) -> str:
    """Mask a single value, keeping a short recognisable prefix/suffix.

    Callers that need zero information leakage should use ``MASK`` semantics;
    this keeps enough shape to debug ("which token is this?") without
    disclosing the secret.
    """
    if not value:
        return MASK
    for name, pattern in CREDENTIAL_PATTERNS:
        match = pattern.fullmatch(value)
        if match:
            if name in {"private_key", "private_key_header", "hex_secret"}:
                return MASK
            text = match.group(0)
            if len(text) <= 8:
                return MASK
            return f"{text[:4]}{MASK}{text[-2:]}"
    return MASK


def _luhn_ok(digits: str) -> bool:
    """The checksum every payment card satisfies and most other numbers do not."""
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _replacer(name: str):
    """A substitution function for one shape, with its own validation."""

    def replace(match: re.Match[str]) -> str:
        if name == "payment_card" and not _luhn_ok(re.sub(r"\D", "", match.group(0))):
            return match.group(0)
        return _mask_match(match)

    return replace


def redact_text(text: str) -> str:
    """Redact every recognised secret/PII shape inside arbitrary text."""
    if not text:
        return text
    result = text
    for name, pattern in ALL_PATTERNS:
        result = pattern.sub(_replacer(name), result)
    return result


def _mask_match(match: re.Match[str]) -> str:
    text = match.group(0)
    # For DSNs keep the scheme so the reader knows what kind of credential it was.
    if "://" in text:
        scheme = text.split("://", 1)[0]
        return f"{scheme}://{MASK}"
    if text.lower().startswith(("bearer", "basic")):
        scheme = text.split(None, 1)[0]
        return f"{scheme} {MASK}"
    return MASK


def sanitize_value(value: Any) -> Any:
    """Redact a single value without key context."""
    return _sanitize(value, sensitive_context=False)


def sanitize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Redact a mapping, honouring sensitive key names at every depth."""
    if not isinstance(payload, dict):
        return {"value": _sanitize(payload, sensitive_context=False)}
    return {
        key: _sanitize(value, sensitive_context=is_sensitive_key(str(key)))
        for key, value in payload.items()
    }


def _sanitize(value: Any, *, sensitive_context: bool) -> Any:
    if isinstance(value, dict):
        if sensitive_context:
            # Everything under a sensitive key is sensitive, including nested keys.
            return {key: _sanitize(item, sensitive_context=True) for key, item in value.items()}
        return sanitize_payload(value)
    if isinstance(value, (list, tuple)):
        sanitized = [_sanitize(item, sensitive_context=sensitive_context) for item in value]
        return type(value)(sanitized) if isinstance(value, tuple) else sanitized
    if isinstance(value, str):
        return MASK if sensitive_context else redact_text(value)
    if sensitive_context and value is not None:
        # A phone number stored as an int is still a phone number. The previous
        # implementation returned non-strings untouched, so {phones:[138...]}
        # survived while {phone:"138..."} was masked.
        return MASK
    return value
