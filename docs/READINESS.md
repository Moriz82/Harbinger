# Readiness

**Current checkout, 2026-09-23 UTC:** Local synthetic checks passed after pagination, off-page evidence refresh, session-expiry, and writable-storage health changes: 285 backend tests and 76 frontend tests, with five role-specific backend skips; TypeScript and the production build passed. The current built browser UI passed the synthetic fixture at three viewports; see the local result at `/home/moriz/.local/state/harbinger-merlin-e2e/browser-current-r2/harbinger/RESULTS.json`. The Dell host is offline, so the changed Docker image, two-VM workflow, and CPTC11 evidence path are **not yet revalidated**. The table below records the earlier checkpoint and must not be used as a current release claim.

This private checkpoint separates current source and local synthetic checks from historical deployment checks on both designated Kali VMs.

Last checked: 2026-09-22 UTC.

| Evidence | Status | Current evidence | Remaining gate |
| --- | --- | --- | --- |
| Backend suite | Pass | The current source passed 251 backend tests. The five skips are Merlin-owned delivery cases, not missing host dependencies. Cross-repository tests now use Harbinger's actual bundle builder and cover merged-upload provenance and restricted harness artifacts. | None for Harbinger-owned backend paths. |
| Frontend source checks | Pass | All 68 frontend tests, TypeScript checks, and the production build passed. | None for automated source checks. |
| Current-host Docker service | Pass | The rebuilt app and networkless parser were healthy. Read-only filesystems, dropped capabilities, process and memory limits, and parser network denial passed. The populated workspace passed backup, restore, integrity verification, and restart. | None for this host. |
| Same-host Harbinger-to-Merlin exchange | Pass | The live encrypted transfer imported four linked records and evidence. The exact replay returned the original receipt. Merlin accepted Harbinger's artifact classification and merge-review fields. | None. |
| HTTPS LAN with individual accounts | Pass | Current-source deployments on Kali VM 1110 and VM 1111 used fresh private-CA certificates. Strict CA checks passed in both directions. The signed direct transfer and draft creation passed. | Re-enroll if either host identity, key, or address changes. |
| Encrypted file fallback | Pass | A prior unconfirmed bundle imported through the encrypted fallback after the compatibility repair. A one-bit change was rejected with HTTP 422. Direct retry of the earlier uncertain send was avoided. | None. |
| Synthetic browser evidence | Partial, current | Nine current captures cover 1366 x 768, 1920 x 1080, and compact 683 x 384 views. Keyboard focus, map selection, the exact italic reminder, reduced motion, truthful offline state, disabled offline writes, and zero browser/network errors passed. | Complete actual 200 percent browser zoom and screen-reader speech. The compact view is only a reflow proxy. |
| Synthetic performance run | Pass on this host | The 10,000-asset and 100,000-relationship fixture passed with 12 sessions. Initial view was 0.178 seconds, search p95 was 0.121 seconds, and save p95 was 0.038 seconds. | None. |
| Kali VM 1110 | Pass | Verified `kali-base-test`, exact MAC and public-key identity, four cores, 8 GiB RAM, existing snapshots, current-source Docker deployment, HTTPS pairing, transfer, parser-receipt review, backup, restore, record retention, and restart. The older 8710 deployment remained healthy. | Keep the accepted snapshots and host-key record with the private release record. |
| Kali VM 1111 | Pass | Verified `kali-cptc-test`, exact MAC and public-key identity, four cores, 8 GiB RAM, existing snapshots, current-source Merlin deployment, pairing, transfer, draft creation, backup, restore, record retention, and restart. The older 8711 deployment remained healthy. | Keep the accepted snapshots and host-key record with the private release record. |

All application checks used synthetic data. See [the rehearsal record](../acceptance/REHEARSAL.md) and [current browser method](../acceptance/BROWSER-QA.md). The companion Merlin release records the current local Ghostwriter check.
