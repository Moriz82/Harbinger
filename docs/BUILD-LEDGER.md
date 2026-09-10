# Build ledger

Requested: approved Harbinger/Merlin plan. Runtime model calls: zero.
Main owns contracts, Python core, integration, release evidence, and publication.

The final harness-boundary review consolidated host and contained-parser
validation into `workspace/parsers/common/harness_validation.py`. Regression
tests cover decoder-depth exhaustion, controlled HTTP rejection and cleanup,
PortCast wire/replay mismatches inside Bubblewrap, and malformed or contract-
drifted peer-transfer attestations.
Current user authorization: Astra for planning and design; Terra or Sol where each fits. Use source and synthetic fixtures only.
Ruling: preserve main as requested; do not create task branches.
Ruling: use separate internal copies of the small application core, not a shared runtime dependency.
Documentation and synthetic-performance package, 2026-09-08:

- Planner brief: supplied by the main task handoff.
- Implementation: Terra agent (`/root/terra_ui_corrections`).
- Runtime model calls: zero.
- Live acceptance claim: none.

Private release acceptance, 2026-09-09:

- Integration and security hardening: main agent with read-only Luna reviews.
- Source: repository code and synthetic fixtures only.
- Added exact origin and port enforcement, signed pre-body peer admission, one-use request nonces, read-only backup source access, atomic backup and restore staging, and failure preservation.
- Live failure tests added immutable SQLite identity reads, sealed backup databases, full staged-file rehashing, bounded parser recovery, and descriptor-leak checks. An independent final review found no release blocker in these areas.
- Dell evidence: Kali VMs 1110 and 1111, private TLS pairing, LAN and encrypted-file exchange, backup and restore, and performance fixtures.
- Runtime model calls: zero.

Frontend redesign and responsive QA, 2026-09-09:

- Design and implementation: Astra agent (`/root/astra_ui_redesign_plan`), `gpt-6-astra`, xhigh.
- Integration and browser QA: main agent.
- Scope: React interface, styles, accessibility behavior, synthetic fixtures, and documentation only.
- Historical verification: 36 frontend tests, TypeScript typecheck, production build, and Docker rebuild. The retained browser evidence is four synthetic PNGs for map and findings at two recorded desktop viewports. There is no retained compact-layout or browser-zoom capture.
- Runtime model calls: zero.

Frontend UI remediation, 2026-09-09:

- Plan and scope: seven confirmed Astra UI findings; implementation by the assigned UI worker, with the evidence-preview contract owned by main.
- Changes: recovered maps restore data and selection; explicit readiness states and manual retry reject stale probe results; event timing says Last server update; images require server media metadata and retain a text fallback; content focus has a visible outline; loaded transfer conflicts remain readable with resolution disabled during outages.
- Verification: 15 new regression cases failed before implementation, then passed. The full frontend suite passed 58 tests. Typecheck, production build, and `git diff --check` passed.
- Evidence audit: all four existing screenshot hashes and PNG dimensions verified; no new captures generated. The screenshots show an earlier interface and do not validate this source revision or prove browser zoom, compact layout, screen-reader behavior, or console/network health.
- Remaining gate: current synthetic browser acceptance. No live data or external service was used.
- Runtime model calls: zero.

Final Astra source remediation, 2026-09-10:

- Changes: defined every workspace color token; prevented unreviewed images from displaying approved wording; exposed upload progress before a record exists; and kept isolated map nodes keyboard-selectable.
- Verification: the full frontend suite passed 66 tests. Typecheck and the production build passed. The build retains the documented large-chunk warning.
- Local browser evidence: the rebuilt synthetic Docker stack passed current-source checks at 1366 x 768, 1920 x 1080, and compact 683 x 384. Graph failure and recovery, readiness failure and recovery, isolated-node keyboard selection, image fallback, retained offline conflicts, disabled offline writes, healthy app restart, skip-link focus, reduced-motion preference, and console/page-error checks passed. Eight current screenshots were added to the manifest.
- Remaining gate: actual 200 percent browser zoom and screen-reader output. Headless Chromium did not apply its zoom shortcut.
- Runtime model calls: zero.

Harness-boundary closure, 2026-09-10:

- Changes: one semantic validator now protects host and contained-parser ingestion; transfer intake verifies the contract hash even when an envelope has no SMB evidence; possible secret-bearing variants use a conservative streaming classifier; and the built wheel includes the pinned contracts and shared validator.
- UI behavior: a failed finding write now states `Not saved` and offers the local draft-file path. A clean loaded revision retains its confirmed saved state during a later readiness outage.
- Verification: 241 backend tests passed with five named environment-dependent skips. All 68 frontend tests, TypeScript typecheck, and the production build passed. An offline wheel contained all required contract files and ran the networkless Bubblewrap parser from a non-editable install.
- Adversarial follow-up: valid JSON Unicode escapes combined with a byte-order mark or more than 4 MiB of padding remain restricted through raw, streamed-path, upload, preview, download, approval, and bundle paths.
- Data handling: conservative marker matches stay restricted and require operator review. They are not a declaration that the data is safe to disclose.
- Runtime model calls: zero.
