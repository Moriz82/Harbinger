# Architecture

Each application is a private, local workspace. They keep separate SQLite state and separate code. They do not share a runtime dependency.

```text
Browser UI -> same-origin FastAPI service -> SQLite state and private artifacts
                               |-> contained, offline parser work (Harbinger)
                               |-> reviewed Ghostwriter adapter (Merlin only)
                               |-> signed, age-encrypted transfer bundle
```

Harbinger stores assets, relationships, uploads, evidence, and technical findings. Merlin receives leads and creates report drafts. A transfer sends selected records in a signed encrypted bundle. It never imports a SQLite database.

Each LAN transfer also has a signed HTTP request envelope. The receiving host verifies the enrolled source, exact recipient, timestamp, one-use nonce, declared size, and body checksum before it reserves the file-transfer slot or reads the body. It rejects stale, replayed, oversized, or changed requests. After decryption, it independently verifies the bundle signature, schema, and record provenance.

The parser accepts only admitted source formats. It runs without a network target. The API records revisions and audit events. The UI keeps a dirty record local until the user saves or discards it. A reviewed local image route admits only bounded PNG, GIF, and JPEG bytes.

The reviewed harness boundary has two stages. The host first validates the pinned contract hash and strict schema. It verifies timestamp order and the five-minute future-clock tolerance, active source card, engagement, key identifier, target-profile binding, bounded resource accounting, and Ed25519 signature. The signature covers the policy, release, frozen plan, target profile, action, module, collector, reservation, reserved counters, consumed counters, review, and observation. Only then does the networkless parser validate the same pinned shape and normalize one asset and one observation. Merge repeats artifact, source, signature, accounting, timestamp, and preview-binding checks. Envelope and observation replay indexes are additive; identifier reuse with changed content is rejected. The parser receives no source-card path and performs no evidence dereference.

The signed original remains in private artifact storage for verification, replay detection, and audit integrity. The ordinary evidence route generates a bounded trust summary and never reads the raw artifact into its response. Raw harness envelopes cannot be downloaded, approved for export, or included in signed transfer bundles. Safe normalized records retain bounded attestation metadata for team review and transfer.

Ghostwriter is a Merlin-only boundary. A lead scribe reviews a fixed draft revision before send. An uncertain result needs reconciliation. Evidence files with a manual attachment state are not uploaded by the adapter.

See [Data handling](DATA-HANDLING.md), [Operations](OPERATIONS.md), and [Readiness](READINESS.md).
