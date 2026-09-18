# MailRakhwala Offline Root CA Trust Store (Step 20)

## Security Boundary & Operational Policy
1. **Passive Isolation**: Captured certificates from PCAP files are NEVER dynamically inserted into this trust store.
2. **Deterministic Baseline**: Anchors are loaded strictly from offline, versioned PEM bundles.
3. **No External Network Access**: The trust engine does not fetch missing intermediates via AIA (Authority Information Access), does not query live OCSP responders, and does not download CRLs.
4. **Trust Anchor Semantics**:
   - `VALIDATED_LOCALLY`: A complete chain of valid signatures terminated at an explicit anchor in this bundle.
   - `NOT_VALIDATED`: Verification failed (expired, self-signed without trust anchor, broken signature, or missing intermediate).
   - `UNAVAILABLE_FROM_PCAP`: No bundle loaded or insufficient capture data.