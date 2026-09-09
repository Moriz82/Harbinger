# Readiness

This is a private release-candidate checkpoint. It records synthetic checks on the development host and both designated Kali VMs.

Last checked: 2026-09-09 UTC.

| Evidence | Status | Current evidence | Remaining gate |
| --- | --- | --- | --- |
| Backend and frontend suites | Pass | 180 backend tests and 36 frontend tests passed. Five environment-dependent tests were skipped. Typecheck and the production build passed after the workspace redesign. | Repeat after a source change. |
| Current-host Docker service | Pass | The rebuilt app and networkless parser passed their health checks on loopback. A networkless backup container read the source through a read-only mount and produced a verified 13-file backup. | None for this host. |
| Same-host Harbinger-to-Merlin exchange | Pass | An encrypted synthetic transfer imported four linked records and one evidence file. A scribe question returned to Harbinger. | None. |
| HTTPS LAN with individual accounts | Pass | Kali VM 1110 and VM 1111 used enrolled identities and the private CA. The latest signed request moved a five-record closure and two evidence files. Merlin imported three new records and recognized two exact duplicates. It returned one new question with four duplicate dependencies. Repeated sends returned the original receipts. | Re-enroll if either host identity, key, or address changes. |
| Encrypted file fallback | Pass | Merlin was stopped before a repeated LAN send. Harbinger returned 503 and retained an uncertain delivery event. The 5,164-byte age bundle then crossed hosts and imported with the original receipt and no second merge. | None. |
| Synthetic browser review | Pass | Six Playwright captures covered the map and finding editor at 1366 x 768, 1920 x 1080, and a 683 x 384 compact-layout check. The exact italic reminder stayed visible. The run found no horizontal overflow, unnamed buttons, missing image alternatives, browser errors, or failed requests. Reviewed desktop screenshots and hashes are in the screenshot manifest. | Native screen-reader and sustained reconnect trials remain separate operational checks. |
| Synthetic performance run | Pass on Kali VM 1110 | The 10,000-asset and 100,000-relationship fixture loaded in 3.918 seconds. Initial view was 0.363 seconds. Search p95 was 0.469 seconds. Save p95 was 0.036 seconds with 12 sessions. | None. |
| Kali VM 1110 | Pass | Verified `kali-base-test`, four cores, 8 GiB RAM, wired `vmbr0`, snapshot chain, Kali 2026.1, source trust, repeat setup, Docker deployment, HTTPS pairing, transfer, an 18-file v6 backup, restore, retained five required records, and restart. | Keep the accepted snapshot and host-key record with the private release record. |
| Kali VM 1111 | Pass | Verified `kali-cptc-test`, four cores, 8 GiB RAM, wired `vmbr0`, snapshot chain, Kali 2026.1, source trust, repeat setup, Merlin deployment, pairing, transfer, backup, restore, retained six required records, and restart. | Keep the accepted snapshot and host-key record with the private release record. |

All listed checks used synthetic data. See [the rehearsal record](../acceptance/REHEARSAL.md). The companion Merlin release passed its separate synthetic Ghostwriter evidence and rendered-document checks.
