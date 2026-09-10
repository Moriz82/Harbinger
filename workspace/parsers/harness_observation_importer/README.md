# Reviewed harness observation

This importer normalizes one signed `harness_observation_v1` envelope after the Harbinger host has verified its enrolled source, engagement, review profile, provenance pins, key, and Ed25519 signature.

The contract admits the original SMB2 security-mode profile and the closed `web.http_jellyfin_public_identity` PortCast profile. A PortCast import creates one candidate web-service observation. Its version remains banner provenance with `vulnerability_assessment: not_performed`; the importer does not infer a CVE or create a finding.

Evidence references remain metadata only. Harbinger records their digest, size, classification, and source-harness availability, but it never receives a local artifact path, raw response bytes, or ciphertext and never fetches the encrypted evidence.
