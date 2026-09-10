# Synthetic rehearsal

Run date: 2026-09-09 UTC.

The Docker rehearsals used synthetic records only.

1. Harbinger imported bounded Nmap XML through the contained parser.
2. The preview showed three assets, two relationships, and two observations.
3. The operator merged the preview, approved synthetic evidence, and created an observed finding lead.
4. Harbinger encrypted the latest lead closure: one selected lead, four dependencies, and two evidence files. Merlin imported three new records and recognized two exact duplicates.
5. The same-host rehearsal imported the records and returned a scribe question.
6. Kali VM 1110 paired with Kali VM 1111 through the private CA and repeated the transfer over HTTPS.
7. A repeated send returned the original receipt.
8. Merlin was stopped. The next send returned 503 without a false success state.
9. The 5,164-byte encrypted file crossed hosts and returned the original receipt without a second merge.
10. Merlin returned one new question and four exact duplicate dependencies.
11. Harbinger created an 18-file v6 backup. Merlin created a 17-file v6 backup. Restore retained the peer enrollment, evidence, finding, lead, question, and Merlin draft.
12. Both four-core, 8 GiB Kali VMs passed the 10,000-asset, 100,000-relationship, 12-session performance thresholds.

The app did not run Nmap or an AI transport. The source file was operator-provided. Original pre-restore state folders remain preserved on both VMs.

The local synthetic signed-import rehearsal generated an ephemeral Ed25519 key, enrolled its public source card by an independently computed fingerprint, accepted one reviewed SMB2 observation, required acknowledgement, and merged one asset plus one observation with no finding. Tampering, wrong engagement, revocation, envelope reuse, observation reuse, malformed JSON, and declared-size cases were rejected. No network, scanner, exploit, external evidence fetch, live data, or harness repository was used.

The UI remediation used synthetic component fixtures and a headless Cytoscape instance. Fifteen regression cases failed before implementation, then passed; the complete frontend suite passed 58 tests. Typecheck, production build, and whitespace validation passed. These checks cover recovered graph contents and selection, readiness retry and stale responses, truthful server-update timing, server-authorized image selection and text fallback, content focus styling, and retained offline conflict details.

On 2026-09-10, the current source was rebuilt in the local synthetic Docker stack. Headless Chromium produced eight reviewed viewport captures: the overview at 1366 x 768, 1920 x 1080, and 683 x 384; graph and readiness failures at 1366 x 768; an isolated-node keyboard state; an image fallback; and a retained conflict after the exact local app container stopped. Automated checks confirmed no page-wide horizontal overflow, no console or page errors, visible italic reminder text, first-tab focus on the skip link, reduced-motion preference recognition, disabled writes after readiness failure, successful readiness retry, usable asset-table fallback after graph failure, successful graph retry, keyboard selection of an isolated node, safe unapproved-image wording, text fallback after image failure, retained conflict revisions after disconnect, and disabled conflict resolution while offline. The app container restarted and returned healthy. The manifest also retains the four historical images. Actual 200 percent browser zoom and screen-reader output remain browser acceptance gates. Headless Chromium ignored zoom shortcuts, so the compact capture is not labeled as zoom evidence.
