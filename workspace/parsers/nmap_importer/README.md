# Nmap importer

Supports Nmap XML, ordinary text, and grepable (`-oG`) text. XML preserves
addresses, hostnames, open services, and completion status; text formats are
lossy and report that limitation. Nmap output is parsed offline with no scanner
execution or network access.

Service endpoints are limited to valid TCP, UDP, or SCTP ports. Invalid or
missing host addresses are skipped with bounded limitations. The dispatcher
tests all three formats and the lossy/partial behavior.

Nmap XML may contain NSE `<script>` elements below a host's `<hostscript>` or
`<port>` element. The importer detects these elements but does not interpret
their IDs, attributes, nested tables, or free-form output. It retains only a
script count and ordinal XML source locations in a generic observation. At most
64 source locations are retained per host and in the import limitation; larger
sets record the full count and that location metadata was truncated. Every
import containing NSE script elements is partial and includes an explicit
unsupported-NSE limitation, even when Nmap reports a successful scan.
