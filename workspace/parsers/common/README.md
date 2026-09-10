# Common parser core

`ParseContext` owns the bounded normalized asset, relationship, and observation
shapes shared by all importers. `archive`, `secret_bearing`, and `safe_text`
implement the existing archive, quarantine, and display limits. The core does
not collect, execute tools, or access the network.

Inputs are already bounded raw bytes. Source provenance is retained through the
normalized locations and quarantine flag; possible secret-bearing content is
kept out of normal views. Archive entries are limited, path checked, JSON-only,
and reject nested archives/databases. Shared behavior is covered by the parser
and backend tests.

The marker classifier streams large files and treats byte-order marks,
whitespace variations, literal markers, and JSON Unicode-escaped markers
conservatively, including combinations that exceed the structured-parser size
limit. A conservative match keeps the artifact restricted for operator review.
It does not certify that an unmatched artifact is safe to disclose.

`harness_validation.py` is the one semantic validator used by the web trust
boundary and the contained parser. It checks strict JSON depth, the pinned
contract hash, timestamps, budgets, PortCast wire receipts, and replay identity.
Transfer intake checks the same contract hash before it accepts typed harness
fragments, including envelopes that contain no SMB evidence. The wheel build
includes the validator and both pinned contract files so an installed parser
does not depend on the source checkout.
