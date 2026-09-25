# Harbinger

Harbinger is a local evidence desk. It imports human-run tool output, maps relationships, and keeps technical finding notes. It does not run scanners, exploits, or model transport. This source repository is public; engagement data and credentials remain private.

## First local start

Use Docker Compose. This local example uses synthetic data and binds only to loopback.

```sh
./manage.sh plan
./manage.sh build
./manage.sh init "Synthetic practice" synthetic http://127.0.0.1:8710 captain
./manage.sh up
./manage.sh status
./manage.sh verify
```

Open `http://127.0.0.1:8710`. Use the password that you entered during `init`. Run `./manage.sh stop` when the desk is not in use.

The default service is local-only. Use the same engagement ID in Harbinger and Merlin. Review [Operations](docs/OPERATIONS.md) before pairing hosts or enabling a LAN listener.

## Guides

- [Architecture](docs/ARCHITECTURE.md)
- [Operations](docs/OPERATIONS.md)
- [Data handling](docs/DATA-HANDLING.md)
- [Development](docs/DEVELOPMENT.md)
- [Readiness](docs/READINESS.md)
- [Third-party inventory](THIRD-PARTY.md)
- [Supported formats](docs/FORMATS.md)
- [Client info stripper](workspace/client_info_stripper/README.md)
