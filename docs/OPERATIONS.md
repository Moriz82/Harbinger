# Operations

Use one private workspace per application. Give each person an individual account. Keep `state/`, backups, transfer bundles, and evidence on approved encrypted storage in client mode.

## Prepare and start

Run these commands from the repository root:

```sh
./manage.sh plan
./manage.sh build
./manage.sh init "ENGAGEMENT NAME" synthetic http://127.0.0.1:8710 captain ENGAGEMENT-ID http://harbinger:8710
./manage.sh up
./manage.sh status
./manage.sh verify
```

Create one engagement UUID and use it on both hosts. Keep the generated application instance IDs different. `init` creates the first account and transfer keys. Use `./manage.sh add-user NAME tester` for each tester. Stop the service before host-side account, key, pairing, backup, or restore work.

## Enable a client LAN listener

Keep `HOST_BIND=127.0.0.1` for local work. For client mode, first verify the encrypted storage check and the approved team address. Use a DNS name that matches the certificate. Use a certificate chain trusted by both application containers.

Place the server certificate and key in `tls/`. Set the container paths in `.env`:

```text
HOST_BIND=TEAM-LAN-ADDRESS
APP_PORT=8710
APP_TLS_CERT=/tls/harbinger.crt
APP_TLS_KEY=/tls/harbinger.key
APP_PEER_CA_BUNDLE=/tls/team-ca.crt
```

`APP_PEER_CA_BUNDLE` is the CA certificate that validates the enrolled Merlin HTTPS certificate. It affects peer transfer only. Include `:8710` in both HTTPS origins when `APP_PORT=8710`. If the origin has no port, set `APP_PORT=443`. A mismatch blocks startup. Do not bypass certificate verification. Confirm the page, login, peer transfer, and reconnect behavior from a second team device before use.

## Pair Harbinger and Merlin

Stop both applications. On each host, create a public pairing card:

```sh
umask 077
./manage.sh peer-card > harbinger-peer.json
```

Exchange the card through the approved team channel. Compare its printed fingerprint through a separate channel. Enroll only after the name, application, engagement, origin, and fingerprint match:

```sh
./manage.sh enroll merlin-peer.json VERIFIED-FINGERPRINT
./manage.sh info
```

When an administrator runs enrollment for an application UID:GID that differs from root, Harbinger validates the root-owned card and uses a private, app-owned temporary copy only for the container command. It removes that copy when enrollment ends.

Start both applications. In Harbinger, select the records, preview the complete transfer set, and check the recipient. Send the exact reviewed transfer. Keep an uncertain result unresolved until the receiving host confirms the bundle ID and manifest hash.

The receiving host admits only a request signed by its enrolled peer. The signature binds the source, recipient, timestamp, one-use nonce, declared length, and body checksum. A rejected or uncertain transfer is never retried automatically.

If the LAN path fails, select **Export encrypted bundle**. Move the `.age` file through the approved method. In Merlin, select **Import encrypted bundle**. Import is idempotent. Do not transfer a SQLite database.

## Enroll a reviewed harness source

Stop Harbinger. Receive the public `harness_source` card through the approved team channel and compare its printed SHA-256 fingerprint through a separate channel. Then run:

```sh
.venv/bin/harbinger --workspace state harness-enroll SOURCE-CARD.json --fingerprint VERIFIED-FINGERPRINT
```

Restart Harbinger and choose `harness_observation_v1` on Imports. Review the source, key, profile, outcome, envelope and observation hashes, asset context, and evidence-reference metadata. Harbinger also verifies that the signed policy, release, frozen plan, target profile, action, module, collector, reservation, and resource counters satisfy the pinned contract. Check the acknowledgement before merge. To revoke a source, stop Harbinger and run:

```sh
.venv/bin/harbinger --workspace state harness-revoke SOURCE-UUID
```

An identical card enrollment and identical envelope import are idempotent. Changed content under an existing source, envelope, or observation identifier is rejected. Rotate a key with a new source identifier and separately verified source card; the old enrollment and revocation remain in the database.

The signed original remains restricted to verification, replay detection, and audit integrity. The Evidence page shows a generated metadata-only trust summary. The download, export-approval, and transfer-bundle paths reject the raw signed envelope. Transfer the normalized observation record when the team needs its bounded attestation metadata.

## Connection loss

The browser shows the last successful sync time. It keeps the loaded view and unsaved text in memory. It disables server writes after connection loss or a refused mutation. An event-stream reconnect does not enable writes by itself; the browser first checks the authenticated `/api/readiness` writer gate. Failed readiness checks keep writes disabled. Save urgent text to a file in the approved encrypted workspace. The browser does not store client prose in local storage.

## Back up and restore

Stop the service. Back up to a new directory:

```sh
./manage.sh stop
./manage.sh parser-receipts
./manage.sh parser-ack JOB-ID error SHA256
./manage.sh backup /APPROVED/NEW/harbinger-backup
```

Verify the receipt and keep the source workspace. Restore only when `state/` is absent. Preserve the old state under a separate name, then restore and verify:

```sh
./manage.sh restore /APPROVED/harbinger-backup
./manage.sh info
./manage.sh verify
```

Start only after the engagement and instance identity are correct.

The backup command mounts the stopped source workspace read-only. It reads committed WAL data when clean shutdown leaves SQLite sidecars. It does not change the source bytes. The backup manifest records the size and SHA-256 checksum of every file. The backup seals its SQLite copy and does not keep WAL sidecars. Restore opens the source in immutable mode and rechecks each staged copy before it publishes the new workspace. If Harbinger finds an input, request, running job, cancel marker, or unsafe parser entry after a restart, it blocks mutations and backup until an operator reviews the queue. Closed response and error receipts remain available for review and do not block new work. Run `parser-receipts` while the services are stopped. Then acknowledge only the reviewed receipt with its exact job ID, kind, and SHA-256 value. `parser-ack` refuses active job files and changed receipts. It atomically moves the exact receipt into protected artifact storage before it records completion. A crash cannot discard the receipt. Repeat the same checksum-bound command after recovery to complete an interrupted acknowledgement. Backup remains blocked until the live queue is empty and includes the archived receipt.
