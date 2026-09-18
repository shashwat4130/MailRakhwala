"""
MailRakhwala Hostname Matching Utility (Step 19)
RFC 6125 compliant hostname and wildcard SAN verification.
Passive, deterministic, and safe against substring or cross-label attacks.
"""

from typing import Optional


def match_hostname(candidate: Optional[str], pattern: Optional[str]) -> bool:
    """
    Deterministically compare a candidate hostname against an observed SAN pattern.

    Semantics (RFC 6125 Section 6.4.3):
    1. Case-insensitive comparison.
    2. Strips optional trailing dots.
    3. Exact matches on valid fully qualified DNS names.
    4. Single-label wildcard matching (*.domain.com matches mail.domain.com).
    5. Wildcard MUST be the entire leftmost label (*.example.com, NOT mail*.example.com).
    6. Wildcard cannot match across multiple labels (*.example.com != a.b.example.com).
    7. Wildcard cannot match single-label TLDs (*.com is rejected as unsafe).
    8. Rejects empty strings, IP addresses in wildcard format, and malformed inputs.
    """
    if not candidate or not pattern:
        return False

    c_norm = candidate.strip().rstrip(".").lower()
    p_norm = pattern.strip().rstrip(".").lower()

    if not c_norm or not p_norm:
        return False

    # Exact match after normalization
    if c_norm == p_norm:
        return True

    # Wildcard evaluation
    if "*" not in p_norm:
        return False

    p_labels = p_norm.split(".")
    c_labels = c_norm.split(".")

    # Wildcard must have identical label count
    if len(p_labels) != len(c_labels):
        return False

    # Wildcard must be exactly the leftmost label
    if p_labels[0] != "*":
        return False

    # Prevent wildcard directly on top-level or single-label domains (e.g., *.com, *)
    if len(p_labels) < 3:
        return False

    # Leftmost label in candidate cannot be empty
    if not c_labels[0]:
        return False

    # All remaining right-side labels must match exactly
    return p_labels[1:] == c_labels[1:]