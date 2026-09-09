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

The importer rejects SQLite files, nested archives, unsafe paths, symlinks, external XML entities, malformed records, and inputs above its limits. It never silently truncates a successful import. Select a new preview after an upload. Merge only the preview bound to the current upload and preview revisions.

Each adapter documents its scope and limits:

- [Nmap](../workspace/parsers/nmap_importer/README.md)
- [Web](../workspace/parsers/web_importer/README.md)
- [PEAS](../workspace/parsers/peas_importer/README.md)
- [BloodHound](../workspace/parsers/bloodhound_importer/README.md)
- [Manual and database/service metadata](../workspace/parsers/manual_importer/README.md)

See [Data handling](DATA-HANDLING.md) before you import client evidence.
