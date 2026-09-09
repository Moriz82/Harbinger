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
