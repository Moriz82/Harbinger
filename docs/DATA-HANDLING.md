# Data handling

Treat source artifacts, evidence, records, transfer keys, and Ghostwriter tokens as confidential. Keep them in the private workspace. Do not put them in screenshots, issue text, or public repositories.

Harbinger accepts saved tool output. It does not run scanners or exploits. The parser is format scoped and networkless. It records partial or unsupported results instead of making an unsupported conclusion.

Signed harness imports contain reviewed observation metadata only. Enroll a public source card after comparing its SHA-256 fingerprint through a separate channel. Revocation is retained, and key rotation uses a new source identifier and card. The signature binds the policy, release, frozen plan, target profile, action, module, collector, reservation, reserved resource counters, consumed resource counters, review, and observation. Harbinger stores the original envelope only as a restricted artifact for verification, replay detection, and audit integrity. Ordinary evidence preview returns a generated trust summary. Raw envelope text, observation payloads, and signature material cannot be previewed, downloaded, approved for export, or placed in a transfer bundle. Safe normalized observation records and their bounded attestation metadata can still be reviewed and transferred. Harbinger never fetches an evidence reference. Conflicting broker asset identifiers and context remain visible as separate imported context for operator review.

The client-info stripper creates an aliased, minimized output. It removes names, addresses, URLs, prose, raw evidence, credentials, and source paths. Its receipt requires human review and does not authorize disclosure. See [its module guide](../workspace/client_info_stripper/README.md).

Transfers use signed, recipient-encrypted bundles. They carry selected records, not database files. A duplicate is not an import. A conflict preserves the encrypted bundle for host review.

Merlin renders untrusted Markdown without raw HTML or external links. External images stay blocked. An authenticated local evidence image can render only after host review and only when it passes the bounded PNG, GIF, or JPEG check. The Ghostwriter adapter sends reviewed prose and an evidence manifest. When the attachment state is `manual_required`, attach the selected evidence files in Ghostwriter yourself.

Use synthetic data for development and acceptance tooling. Do not use client data in local examples or performance runs.
