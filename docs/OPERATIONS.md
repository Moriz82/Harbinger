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

Start both applications. In Harbinger, select the records, preview the complete transfer set, and check the recipient. Send the exact reviewed transfer. Keep an uncertain result unresolved until the receiving host confirms the bundle ID and manifest hash.

The receiving host admits only a request signed by its enrolled peer. The signature binds the source, recipient, timestamp, one-use nonce, declared length, and body checksum. A rejected or uncertain transfer is never retried automatically.

If the LAN path fails, select **Export encrypted bundle**. Move the `.age` file through the approved method. In Merlin, select **Import encrypted bundle**. Import is idempotent. Do not transfer a SQLite database.

## Connection loss

The browser shows the last successful sync time. It keeps the loaded view and unsaved text in memory. It disables server writes until the event connection returns. Save urgent text to a file in the approved encrypted workspace. The browser does not store client prose in local storage.

## Back up and restore

Stop the service. Back up to a new directory:

```sh
./manage.sh stop
./manage.sh backup /APPROVED/NEW/harbinger-backup
```

Verify the receipt and keep the source workspace. Restore only when `state/` is absent. Preserve the old state under a separate name, then restore and verify:

```sh
./manage.sh restore /APPROVED/harbinger-backup
./manage.sh info
./manage.sh verify
```

Start only after the engagement and instance identity are correct.

The backup manifest records the size and SHA-256 checksum of every file. The backup seals its SQLite copy and does not keep WAL sidecars. Restore opens the source in immutable mode and rechecks each staged copy before it publishes the new workspace. If Harbinger finds an input, request, running job, cancel marker, or unsafe parser entry after a restart, it blocks mutations and backup until an operator reviews the queue. Closed response and error receipts remain available for review and do not block new work. Review and archive closed receipts before backup because the backup refuses a non-empty parser queue.
