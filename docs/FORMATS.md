# Harbinger formats

Harbinger accepts saved source output. It does not run collection tools. Each import is bounded and parsed offline. A parse can be complete, partial, quarantined, or unsupported.

| UI value | Accepted signature | Stored result | Compatibility state |
| --- | --- | --- | --- |
| `nmap_xml` | XML root `nmaprun` with host and run status elements | Addresses, host names, open services, and completion state | Preferred. Synthetic vulnerable, empty, malformed, and partial fixtures pass. Live tool-version matrix is pending. |
| `nmap_text` | Nmap normal output with recognized report and port rows | Lossy host and service observations | Partial by design. Review every limitation. |
| `nmap_gnmap` | Nmap `-oG` host rows | Lossy host and service observations | Partial by design. Review every limitation. |
| `har` | HAR 1.2 JSON with `log.entries` | HTTP exchange observations | Query values and bodies do not become map labels. |
| `zap_json` | ZAP JSON report with site and alert records | Scanner candidates as observations | A ZAP alert is not a confirmed finding. |
| `burp_xml` | Burp XML export with item records | Request and response observations | Credential-bearing content is quarantined. |
| `linpeas_text` | Text with the reviewed LinPEAS signature | Section indexes and partial observations | No privilege or vulnerability conclusion. |
| `winpeas_text` | Text with the reviewed WinPEAS signature | Section indexes and partial observations | No privilege or vulnerability conclusion. |
| `bloodhound` | BloodHound v5 object JSON or safe JSON ZIP | Objects and evidenced membership relationships | Unsupported collection shapes remain evidence only. |
| `manual_json` | Manual observation schema version 1 | Declared assets, observations, and relationships | The declared track must be network, web, Linux, Windows/AD, or database/service. |
| `manual_json` with database/service track | The same schema with structured service identity, configuration, or role observations | Database and service metadata | Operator-provided evidence only. No database connection runs. |
| `harness_observation_v1` | One reviewed, Ed25519-signed JSON envelope from an enrolled `reviewed_broker` source | One Windows/AD host and one typed SMB2 security-mode observation | 4 MiB maximum. `observed` and `not_observed` are complete; `inconclusive`, `unsupported`, and `error` are partial. No finding is created and evidence references are never fetched. |

The importer rejects SQLite files, nested archives, unsafe paths, symlinks, external XML entities, malformed records, and inputs above its limits. It never silently truncates a successful import. Select a new preview after an upload. Merge only the preview bound to the current upload and preview revisions.

Each adapter documents its scope and limits:

- [Nmap](../workspace/parsers/nmap_importer/README.md)
- [Web](../workspace/parsers/web_importer/README.md)
- [PEAS](../workspace/parsers/peas_importer/README.md)
- [BloodHound](../workspace/parsers/bloodhound_importer/README.md)
- [Manual and database/service metadata](../workspace/parsers/manual_importer/README.md)
- [Reviewed harness observation](../workspace/parsers/harness_observation_importer/README.md)

The harness contract is pinned by `contracts/HARNESS_CONTRACT_SHA256`. Every object rejects extra, missing, and null fields. Each envelope contains exactly one observation and uses the exact SMB2 signing vocabulary `signing_required`, `signing_enabled`, `signing_disabled`, or `unknown`.

The signed execution provenance contains fixed policy, release, frozen-plan, target-profile, action, module, collector, and reservation identities. Versioned items include a positive integer version and lowercase SHA-256 hash. The reservation records both reserved and consumed counts for TCP connects, UDP datagrams, protocol requests, transmitted bytes, received bytes, wall time, CPU time, processes, output bytes, and authentication attempts. The SMB2 profile ceilings are 2 connects, 1 datagram, 2 requests, 4 KiB sent, 16 KiB received, 15 seconds wall time, 10 seconds CPU time, 1 process, 16 KiB output, and 0 authentication attempts. A consumed count cannot exceed its reserved count.

The observation time must be at or before review time, which must be at or before envelope issuance. A timestamp more than five minutes ahead of the Harbinger host clock is rejected. Old offline bundles are not rejected solely because of age. The restricted original is unavailable through ordinary evidence preview, download, export approval, and team-transfer routes. Those surfaces use safe trust or normalized attestation metadata only.

See [Data handling](DATA-HANDLING.md) before you import client evidence.
