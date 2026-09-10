import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import uuid
from pathlib import Path
import shutil

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from workspace.harness_trust import (
    MAX_HARNESS_BYTES,
    classify_harness_artifact,
    classify_harness_artifact_path,
    enroll_harness_source,
    parse_harness_json,
    revoke_harness_source,
    validate_harness_envelope,
    verify_harness_observation,
)
from workspace.cli import initialize
from workspace.auth import add_user
from workspace.server import create_app
from workspace.isolation import run_parser
from workspace.parsers import parse
from workspace.parsers.common import (
    parse_harness_json as parse_contained_harness_json,
    validate_harness_envelope as validate_contained_harness_envelope,
)
from workspace.store import canonical, digest
from workspace.transfer import build_bundle, preview_bundle, validate_record_data
import workspace.transfer as transfer_module


ENGAGEMENT = "00000000-0000-4000-8000-000000000001"
PORTCAST_PROFILE = "web.http_jellyfin_public_identity"
PORTCAST_REPLAY_ID = "debd0995-f1b6-5925-a3d7-71dc9aea4a81"
PORTCAST_PINS = {
    "source_engagement_id": "engagement",
    "policy_sha256": "1" * 64,
    "release_sha256": "2" * 64,
    "module_sha256": "4" * 64,
    "parser_sha256": "5" * 64,
    "catalog_sha256": "d37bc4a0ba5368e02306f52cce5927d5a5db6e7dee90dda0cc0ee3d243e66113",
    "profile_sha256": "2acbea838777e029076eb93eb039170f806713d3c8fe9724dacb7827ed2322a3",
    "operation_sha256": "e60c94321ac232504c22b1d55e9702a2526f9a0022284b6d9ef7b2c980943fe6",
    "worker_sha256": "472620e6112b00882f480ea4a0209e8dcdab9e0c54ba98ae2bef86c07342f400",
    "runtime_pinset_sha256": "9bcaeaa02a0c9f52b1b32c4259a35043b9dd0caec55f6fec150ec6f5a722df16",
}


@pytest.fixture
def store(tmp_path):
    return initialize(tmp_path / "state", "http://127.0.0.1:8710", "Synthetic practice", engagement_id=ENGAGEMENT)


def source_card(key, *, engagement_id=ENGAGEMENT, source_id=None, key_id="fixture-key-1"):
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        "schema_version": 1,
        "kind": "harness_source",
        "source_id": source_id or str(uuid.uuid4()),
        "name": "Synthetic reviewed broker",
        "engagement_id": engagement_id,
        "role": "reviewed_broker",
        "key_id": key_id,
        "algorithm": "Ed25519",
        "public_key": base64.b64encode(public).decode(),
        "profiles": ["cptc11_smb2_security_mode_v1"],
    }


def portcast_source_card(key, **changes):
    card = source_card(key)
    card["profiles"] = [PORTCAST_PROFILE]
    card["profile_pins"] = {PORTCAST_PROFILE: copy.deepcopy(PORTCAST_PINS)}
    card.update(changes)
    return card


def signed_envelope(key, card, *, outcome="observed", security_mode="signing_required", envelope_id=None, observation_id=None):
    reserved = {
        "tcp_connect_attempts": 2,
        "udp_datagrams": 1,
        "protocol_requests": 2,
        "transmitted_bytes": 4096,
        "received_bytes": 16384,
        "wall_time_ms": 15000,
        "cpu_time_ms": 10000,
        "processes": 1,
        "output_bytes": 16384,
        "authentication_attempts": 0,
    }
    value = {
        "schema_version": 1,
        "kind": "harness_observation_v1",
        "envelope_id": envelope_id or str(uuid.uuid4()),
        "engagement_id": card["engagement_id"],
        "producer": {"source_id": card["source_id"], "role": "reviewed_broker", "key_id": card["key_id"]},
        "issued_at": "2026-09-09T12:00:00.000000Z",
        "review": {"status": "reviewed", "review_id": str(uuid.uuid4()), "reviewed_at": "2026-09-09T11:59:00.000000Z"},
        "profile": {"name": "cptc11_smb2_security_mode_v1", "version": 1},
        "execution": {
            "policy": {"id": "cptc11.readonly", "version": 3, "sha256": "1" * 64},
            "release": {"id": "cptc-harness", "version": 7, "sha256": "2" * 64},
            "frozen_plan": {"id": str(uuid.uuid4()), "sha256": "3" * 64},
            "target_profile": {"id": "cptc11_smb2_security_mode_v1", "version": 1, "sha256": "4" * 64},
            "action_id": str(uuid.uuid4()),
            "module": {"id": "network.nse_smb2_security_mode", "version": 1, "sha256": "5" * 64},
            "collector": {"id": "connected-relay", "version": 2, "sha256": "6" * 64},
            "reservation": {
                "id": str(uuid.uuid4()),
                "reserved": reserved,
                "consumed": {**reserved, "transmitted_bytes": 768, "received_bytes": 2048, "wall_time_ms": 480, "cpu_time_ms": 200, "output_bytes": 512},
            },
        },
        "observation": {
            "observation_id": observation_id or str(uuid.uuid4()),
            "observed_at": "2026-09-09T11:58:00.000000Z",
            "outcome": outcome,
            "asset": {
                "asset_key": "fixture-dc-01",  # gitleaks:allow synthetic stable identifier
                "label": "Fixture DC 01",
                "kind": "host",
                "track": "windows_ad",
                "identifiers": [{"type": "fqdn", "value": "dc01.synthetic.test"}],
                "context": {"domain": "synthetic.test", "role": "domain_controller", "segment": "fixture", "source_locator": "broker:asset:1"},
            },
            "detector": {"name": "smb2_security_mode", "version": 1, "deterministic": True},
            "result": {"protocol": "smb2", "port": 445, "security_mode": security_mode, "dialect": "SMB 3.1.1"},
            "evidence_refs": [{"evidence_id": str(uuid.uuid4()), "sha256": "a" * 64, "size": 128, "media_type": "application/json"}],
        },
    }
    value["signature"] = {
        "algorithm": "Ed25519",
        "encoding": "base64",
        "key_id": card["key_id"],
        "value": base64.b64encode(key.sign(canonical(value).encode())).decode(),
    }
    return value


def portcast_envelope(key, card, *, envelope_id=None, observation_id=PORTCAST_REPLAY_ID):
    reserved = {
        "tcp_connects": 1,
        "udp_datagrams": 0,
        "tls_handshakes": 0,
        "protocol_requests": 1,
        "tx_bytes": 256,
        "rx_bytes": 8192,
        "capture_bytes": 8192,
        "authentication_attempts": 0,
    }
    pins = card["profile_pins"][PORTCAST_PROFILE]
    value = {
        "schema_version": 1,
        "kind": "harness_observation_v1",
        "envelope_id": envelope_id or str(uuid.uuid4()),
        "engagement_id": card["engagement_id"],
        "producer": {"source_id": card["source_id"], "role": "reviewed_broker", "key_id": card["key_id"]},
        "issued_at": "2026-09-09T12:00:00.000000Z",
        "review": {"status": "reviewed", "review_id": str(uuid.uuid4()), "reviewed_at": "2026-09-09T11:59:00.000000Z"},
        "profile": {"name": PORTCAST_PROFILE, "version": 1},
        "execution": {
            "source_engagement_id": pins["source_engagement_id"],
            "policy": {"id": "revision", "sha256": pins["policy_sha256"]},
            "release": {"id": "harness-release", "sha256": pins["release_sha256"]},
            "frozen_plan": {"id": "wave-one", "sha256": "3" * 64},
            "target_profile": {
                "id": PORTCAST_PROFILE,
                "version": 1,
                "target_id": "cptc11-prod-portcast",
                "catalog_sha256": pins["catalog_sha256"],
                "profile_sha256": pins["profile_sha256"],
                "operation_sha256": pins["operation_sha256"],
                "runtime_pinset_sha256": pins["runtime_pinset_sha256"],
            },
            "action_id": "portcast-action",
            "module": {"id": "web.portcast_identity", "version": "1.0.0", "sha256": pins["module_sha256"]},
            "collector": {"id": "portcast-http-identity-v1", "version": 1, "worker_sha256": pins["worker_sha256"]},
            "parser": {"id": "portcast.public_identity.v1", "version": 1, "sha256": pins["parser_sha256"]},
            "reservation": {
                "id": "attempt-portcast-action",
                "reserved": reserved,
                "consumed": {**reserved, "tx_bytes": 103, "rx_bytes": 161, "capture_bytes": 161},
            },
        },
        "observation": {
            "observation_id": observation_id,
            "observed_at": "2026-09-09T11:58:00.000000Z",
            "outcome": "observed",
            "asset": {
                "asset_key": "service:10.0.1.30:8096/jellyfin",
                "label": "Jellyfin Server 10.10.7",
                "kind": "service",
                "track": "web",
                "identifiers": [{"type": "ipv4", "value": "10.0.1.30"}],
                "context": {"target_id": "cptc11-prod-portcast", "endpoint": "http://10.0.1.30:8096/System/Info/Public"},
            },
            "detector": {"name": "portcast_public_identity", "version": 1, "deterministic": True},
            "result": {
                "check_id": "portcast_public_identity",
                "state": "candidate",
                "component_id": "service:10.0.1.30:8096/jellyfin",
                "ecosystem": "semver",
                "product": "Jellyfin Server",
                "version": "10.10.7",
                "provenance": "banner",
                "protocol": "http",
                "port": 8096,
                "vulnerability_assessment": "not_performed",
            },
            "evidence_refs": [{
                "evidence_id": "encrypted-artifact",
                "sha256": "a" * 64,
                "size": 161,
                "media_type": "application/http",
                "classification": "client_confidential_human_only",
                "availability": "source_harness_encrypted_only",
            }],
        },
    }
    return resign(key, value)


def resign(key, value):
    value.pop("signature", None)
    value["signature"] = {
        "algorithm": "Ed25519",
        "encoding": "base64",
        "key_id": value["producer"]["key_id"],
        "value": base64.b64encode(key.sign(canonical(value).encode())).decode(),
    }
    return value


@pytest.fixture
def harness(store):
    key = Ed25519PrivateKey.generate()
    card = source_card(key)
    enroll_harness_source(store, card, digest(card), "fixture")
    return key, card


def test_signed_reviewed_observation_is_verified_and_normalized(store, harness):
    key, card = harness
    envelope = signed_envelope(key, card)
    raw = canonical(envelope).encode()

    trust = verify_harness_observation(store, raw)
    result = parse(raw, "harness_observation_v1")

    assert trust["trusted"] is True
    assert trust["source_id"] == card["source_id"]
    assert trust["profile"] == "cptc11_smb2_security_mode_v1"
    assert trust["outcome"] == "observed"
    assert result["complete"] is True
    assert result["assets"] == [{
        "id": "fixture-dc-01", "label": "Fixture DC 01", "kind": "host", "track": "windows_ad",
        "data": {"asset_key": "fixture-dc-01", "identifiers": [{"type": "fqdn", "value": "dc01.synthetic.test"}], "context": {"domain": "synthetic.test", "role": "domain_controller", "segment": "fixture", "source_locator": "broker:asset:1"}},  # gitleaks:allow synthetic stable identifier
    }]
    assert result["observations"][0]["facts"]["result"]["security_mode"] == "signing_required"
    assert result["observations"][0]["facts"]["evidence_refs"][0]["sha256"] == "a" * 64
    assert result["observations"][0]["facts"]["harness_attestation"]["source_id"] == card["source_id"]
    assert "signature" not in json.dumps(result)


def test_portcast_envelope_normalizes_one_candidate_service_without_raw_evidence(store):
    key = Ed25519PrivateKey.generate()
    card = portcast_source_card(key)
    enroll_harness_source(store, card, digest(card), "fixture")
    envelope = portcast_envelope(key, card)
    raw = canonical(envelope).encode()

    trust = verify_harness_observation(store, raw)
    result = parse(raw, "harness_observation_v1")

    assert trust["profile"] == PORTCAST_PROFILE
    assert trust["observation_id"] == PORTCAST_REPLAY_ID
    assert result["complete"] is True
    assert result["relationships"] == []
    assert result["assets"] == [{
        "id": "service:10.0.1.30:8096/jellyfin",
        "label": "Jellyfin Server 10.10.7",
        "kind": "service",
        "track": "web",
        "data": {
            "asset_key": "service:10.0.1.30:8096/jellyfin",
            "identifiers": [{"type": "ipv4", "value": "10.0.1.30"}],
            "context": {"target_id": "cptc11-prod-portcast", "endpoint": "http://10.0.1.30:8096/System/Info/Public"},
        },
    }]
    assert len(result["observations"]) == 1
    observation = result["observations"][0]
    assert observation["summary"] == "Jellyfin Server 10.10.7 public identity (candidate)"
    assert observation["location"] == "reviewed harness observation"
    assert observation["facts"]["result"]["state"] == "candidate"
    assert observation["facts"]["result"]["vulnerability_assessment"] == "not_performed"
    assert observation["facts"]["harness_attestation"]["execution"]["action_id"] == "portcast-action"
    encoded = canonical(result)
    for forbidden in ("artifact_relpath", ".age", "raw_body", "ciphertext", "CVE-"):
        assert forbidden not in encoded


def test_portcast_source_requires_exact_enrolled_provenance_pins(store):
    key = Ed25519PrivateKey.generate()
    missing = source_card(key)
    missing["profiles"] = [PORTCAST_PROFILE]
    with pytest.raises(ValueError, match="provenance pins"):
        enroll_harness_source(store, missing, digest(missing), "fixture")

    card = portcast_source_card(key)
    enroll_harness_source(store, card, digest(card), "fixture")
    changed = portcast_envelope(key, card)
    changed["execution"]["module"]["sha256"] = "f" * 64
    with pytest.raises(ValueError, match="provenance pins"):
        verify_harness_observation(store, canonical(resign(key, changed)).encode())


def test_portcast_observation_id_is_the_semantic_uuidv5_replay_identity(store):
    key = Ed25519PrivateKey.generate()
    card = portcast_source_card(key)
    enroll_harness_source(store, card, digest(card), "fixture")
    valid = portcast_envelope(key, card)
    assert verify_harness_observation(store, canonical(valid).encode())["observation_id"] == PORTCAST_REPLAY_ID

    changed_id = portcast_envelope(key, card, observation_id=str(uuid.uuid4()))
    with pytest.raises(ValueError, match="replay identity"):
        verify_harness_observation(store, canonical(changed_id).encode())

    changed_action = portcast_envelope(key, card)
    changed_action["execution"]["action_id"] = "other-action"
    with pytest.raises(ValueError, match="replay identity"):
        verify_harness_observation(store, canonical(resign(key, changed_action)).encode())


def test_portcast_schema_rejects_raw_paths_cves_and_incomplete_wire_receipts(store):
    key = Ed25519PrivateKey.generate()
    card = portcast_source_card(key)
    enroll_harness_source(store, card, digest(card), "fixture")
    mutations = []
    raw_path = portcast_envelope(key, card)
    raw_path["observation"]["evidence_refs"][0]["artifact_relpath"] = "evidence/raw.age"
    mutations.append(raw_path)
    cve = portcast_envelope(key, card)
    cve["observation"]["result"]["cve_ids"] = ["CVE-2026-0001"]
    mutations.append(cve)
    incomplete = portcast_envelope(key, card)
    incomplete["execution"]["reservation"]["consumed"]["capture_bytes"] = 160
    mutations.append(incomplete)
    no_request = portcast_envelope(key, card)
    no_request["execution"]["reservation"]["consumed"]["protocol_requests"] = 0
    mutations.append(no_request)

    for value in mutations:
        with pytest.raises(ValueError):
            verify_harness_observation(store, canonical(resign(key, value)).encode())


def test_contained_parser_rejects_bad_portcast_wire_receipt_and_replay_identity():
    key = Ed25519PrivateKey.generate()
    card = portcast_source_card(key)

    bad_receipt = portcast_envelope(key, card)
    bad_receipt["execution"]["reservation"]["consumed"]["capture_bytes"] = 160
    with pytest.raises(ValueError, match="wire receipt"):
        parse(canonical(resign(key, bad_receipt)).encode(), "harness_observation_v1")

    bad_replay = portcast_envelope(key, card, observation_id=str(uuid.uuid4()))
    with pytest.raises(ValueError, match="replay identity"):
        parse(canonical(bad_replay).encode(), "harness_observation_v1")


@pytest.mark.skipif(not shutil.which("bwrap"), reason="bubblewrap is required for the contained parser")
@pytest.mark.parametrize("mutation", ("wire_receipt", "replay_identity"))
def test_bubblewrap_parser_rejects_bad_portcast_semantics(tmp_path, mutation):
    key = Ed25519PrivateKey.generate()
    envelope = portcast_envelope(key, portcast_source_card(key))
    if mutation == "wire_receipt":
        envelope["execution"]["reservation"]["consumed"]["capture_bytes"] = 160
        resign(key, envelope)
    else:
        envelope["observation"]["observation_id"] = str(uuid.uuid4())
        resign(key, envelope)
    source = tmp_path / f"{mutation}.json"
    source.write_bytes(canonical(envelope).encode())

    with pytest.raises(RuntimeError, match="contained parser did not finish"):
        run_parser(source, "harness_observation_v1")


def test_checked_in_harness_contract_hash():
    contract = Path(__file__).parents[1] / "contracts" / "harness-observation-v1.schema.json"
    expected = (contract.parent / "HARNESS_CONTRACT_SHA256").read_text().strip()
    assert hashlib.sha256(contract.read_bytes()).hexdigest() == expected


@pytest.mark.parametrize("outcome,complete", [("observed", True), ("not_observed", True), ("inconclusive", False), ("unsupported", False), ("error", False)])
def test_outcome_controls_completeness(harness, outcome, complete):
    key, card = harness
    result = parse(canonical(signed_envelope(key, card, outcome=outcome)).encode(), "harness_observation_v1")
    assert result["complete"] is complete
    assert bool(result["limitations"]) is (not complete)


def test_trust_rejects_tampering_wrong_engagement_and_revocation(store, harness):
    key, card = harness
    raw = canonical(signed_envelope(key, card)).encode()
    tampered = json.loads(raw)
    tampered["observation"]["result"]["security_mode"] = "signing_disabled"
    with pytest.raises(ValueError):
        verify_harness_observation(store, canonical(tampered).encode())

    wrong = signed_envelope(key, {**card, "engagement_id": str(uuid.uuid4())})
    with pytest.raises(ValueError):
        verify_harness_observation(store, canonical(wrong).encode())

    revoke_harness_source(store, card["source_id"], "fixture")
    with pytest.raises(ValueError):
        verify_harness_observation(store, raw)


@pytest.mark.parametrize("raw", [
    b'{"schema_version":1,"schema_version":1}',
    b'\xef\xbb\xbf{}',
    b'{"number":NaN}',
    b'{} trailing',
    b'\xff',
])
def test_strict_json_rejects_ambiguous_encodings(raw):
    with pytest.raises(ValueError):
        parse_harness_json(raw)


def test_deep_json_is_a_controlled_validation_error_at_both_boundaries():
    raw = (b'{"nested":' * 1100) + b'null' + (b'}' * 1100)

    for parser in (parse_harness_json, parse_contained_harness_json):
        with pytest.raises(ValueError, match="nesting"):
            parser(raw)


def test_host_and_contained_parser_share_one_semantic_validator():
    assert validate_harness_envelope is validate_contained_harness_envelope


def test_contract_rejects_extra_fields_and_wrong_vocabulary(harness):
    key, card = harness
    extra = signed_envelope(key, card)
    extra["observation"]["result"]["extra"] = True
    with pytest.raises(ValueError):
        parse(canonical(extra).encode(), "harness_observation_v1")
    wrong = signed_envelope(key, card, security_mode="required")
    with pytest.raises(ValueError):
        parse(canonical(wrong).encode(), "harness_observation_v1")
    mismatched_identifier = signed_envelope(key, card)
    mismatched_identifier["observation"]["asset"]["identifiers"] = [{"type": "ipv4", "value": "999.999.999.999"}]
    with pytest.raises(ValueError):
        parse(canonical(mismatched_identifier).encode(), "harness_observation_v1")


def test_contract_requires_complete_typed_execution_provenance(harness):
    key, card = harness
    changes = []

    missing = signed_envelope(key, card)
    del missing["execution"]["policy"]
    changes.append(missing)

    null_version = signed_envelope(key, card)
    null_version["execution"]["release"]["version"] = None
    changes.append(null_version)

    unknown = signed_envelope(key, card)
    unknown["execution"]["collector"]["unreviewed"] = True
    changes.append(unknown)

    invalid_id = signed_envelope(key, card)
    invalid_id["execution"]["module"]["id"] = "module with spaces"
    changes.append(invalid_id)

    excessive = signed_envelope(key, card)
    excessive["execution"]["reservation"]["reserved"]["tcp_connect_attempts"] = 3
    changes.append(excessive)

    for value in changes:
        with pytest.raises(ValueError):
            parse(canonical(value).encode(), "harness_observation_v1")


def test_resource_consumption_cannot_exceed_the_signed_reservation(harness):
    key, card = harness
    value = signed_envelope(key, card)
    value["execution"]["reservation"]["reserved"]["tcp_connect_attempts"] = 1
    value["execution"]["reservation"]["consumed"]["tcp_connect_attempts"] = 2
    with pytest.raises(ValueError, match="consumption exceeds"):
        parse(canonical(value).encode(), "harness_observation_v1")


def test_execution_provenance_is_covered_by_the_signature(store, harness):
    key, card = harness
    changes = (
        (("execution", "policy", "sha256"), "f" * 64),
        (("execution", "release", "sha256"), "f" * 64),
        (("execution", "frozen_plan", "sha256"), "f" * 64),
        (("execution", "target_profile", "sha256"), "f" * 64),
        (("execution", "action_id"), "00000000-0000-4000-8000-000000000099"),
        (("execution", "module", "sha256"), "f" * 64),
        (("execution", "collector", "sha256"), "f" * 64),
        (("execution", "reservation", "id"), "00000000-0000-4000-8000-000000000098"),
        (("execution", "reservation", "reserved", "transmitted_bytes"), 4000),
        (("execution", "reservation", "consumed", "transmitted_bytes"), 769),
    )
    for path, replacement in changes:
        value = signed_envelope(key, card)
        target = value
        for field in path[:-1]:
            target = target[field]
        target[path[-1]] = replacement
        with pytest.raises(ValueError, match="signature verification failed"):
            verify_harness_observation(store, canonical(value).encode())


def test_timestamp_order_future_tolerance_and_offline_age(store, harness):
    key, card = harness
    old = signed_envelope(key, card)
    old["observation"]["observed_at"] = "2000-01-01T00:00:00.000000Z"
    old["review"]["reviewed_at"] = "2000-01-01T00:01:00.000000Z"
    old["issued_at"] = "2000-01-01T00:02:00.000000Z"
    assert verify_harness_observation(store, canonical(resign(key, old)).encode())["trusted"] is True

    wrong_order = signed_envelope(key, card)
    wrong_order["observation"]["observed_at"] = "2026-09-09T12:00:00.000000Z"
    wrong_order["review"]["reviewed_at"] = "2026-09-09T11:59:00.000000Z"
    with pytest.raises(ValueError, match="required order"):
        verify_harness_observation(store, canonical(resign(key, wrong_order)).encode())

    future = signed_envelope(key, card)
    base = datetime.now(timezone.utc) + timedelta(days=1)
    stamp = lambda value: value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    future["observation"]["observed_at"] = stamp(base)
    future["review"]["reviewed_at"] = stamp(base + timedelta(seconds=1))
    future["issued_at"] = stamp(base + timedelta(seconds=2))
    with pytest.raises(ValueError, match="too far in the future"):
        verify_harness_observation(store, canonical(resign(key, future)).encode())


def test_input_and_declared_evidence_limits(harness):
    key, card = harness
    value = signed_envelope(key, card)
    value["observation"]["evidence_refs"][0]["size"] = 16 * 1024**2 + 1
    with pytest.raises(ValueError):
        parse(canonical(value).encode(), "harness_observation_v1")
    with pytest.raises(ValueError):
        parse_harness_json(b" " * (4 * 1024**2 + 1))


def test_source_enrollment_is_idempotent_and_identity_changes_are_retained(store):
    key = Ed25519PrivateKey.generate()
    card = source_card(key)
    first = enroll_harness_source(store, card, digest(card), "fixture")
    second = enroll_harness_source(store, copy.deepcopy(card), digest(card), "fixture")
    assert first == second
    changed = {**card, "name": "Changed identity"}
    with pytest.raises(ValueError):
        enroll_harness_source(store, changed, digest(changed), "fixture")
    revoke_harness_source(store, card["source_id"], "fixture")
    with store.connect() as connection:
        row = connection.execute("SELECT status,revoked_at FROM harness_sources WHERE source_id=?", (card["source_id"],)).fetchone()
    assert row["status"] == "revoked" and row["revoked_at"]


def test_verified_view_contains_hashes_without_raw_content(store, harness):
    key, card = harness
    envelope = signed_envelope(key, card)
    raw = canonical(envelope).encode()
    trust = verify_harness_observation(store, raw)
    assert trust["signed_sha256"] == hashlib.sha256(canonical({k: v for k, v in envelope.items() if k != "signature"}).encode()).hexdigest()
    assert trust["observation_sha256"] == hashlib.sha256(canonical(envelope["observation"]).encode()).hexdigest()
    assert "Fixture DC 01" not in canonical(trust)


def harness_client(store, *, raise_server_exceptions=True):
    add_user(store, "host", "captain", "synthetic-test-password", "Harbinger")
    client = TestClient(
        create_app(store.root),
        base_url="http://127.0.0.1:8710",
        headers={"Origin": "http://127.0.0.1:8710"},
        raise_server_exceptions=raise_server_exceptions,
    )
    response = client.post("/api/login", json={"name": "host", "password": "synthetic-test-password"})
    assert response.status_code == 200
    client.headers["X-CSRF-Token"] = response.json()["csrf"]
    return client


def upload_envelope(client, envelope):
    return client.post(
        "/api/uploads",
        data={"format": "harness_observation_v1"},
        files={"file": ("fixture.json", canonical(envelope).encode(), "application/json")},
    )


def test_deep_harness_upload_returns_422_and_removes_staged_bytes(store):
    raw = (b'{"nested":' * 1100) + b'null' + (b'}' * 1100)
    with harness_client(store, raise_server_exceptions=False) as client:
        response = client.post(
            "/api/uploads",
            data={"format": "harness_observation_v1"},
            files={"file": ("deep.json", raw, "application/json")},
        )

    assert response.status_code == 422
    assert "Traceback" not in response.text
    assert list((store.root / "artifacts").iterdir()) == []
    assert store.records("upload") == []


def test_server_readiness_reports_the_writer_gate(store):
    with harness_client(store) as client:
        assert client.get("/api/readiness").json() == {"write_ready": True}
        client.app.state.store.blocked = "Synthetic writer block"
        response = client.get("/api/readiness")
        assert response.status_code == 503
        assert response.json()["detail"] == "Synthetic writer block"


def test_server_readiness_checks_the_same_private_storage_gate_as_a_write(store):
    artifacts = store.root / "artifacts"
    with harness_client(store) as client:
        artifacts.chmod(0o755)
        try:
            response = client.get("/api/readiness")
            assert response.status_code == 503
            assert "Private storage permissions changed" in response.json()["detail"]
        finally:
            artifacts.chmod(0o700)


def test_server_requires_acknowledgement_and_revalidates_before_merge(store, harness, monkeypatch):
    key, card = harness
    envelope = signed_envelope(key, card)
    monkeypatch.setattr("workspace.server.run_parser", lambda path, format: parse(path.read_bytes(), format))
    with harness_client(store) as client:
        uploaded = upload_envelope(client, envelope)
        assert uploaded.status_code == 200
        upload = uploaded.json()
        assert upload["data"]["harness_trust"]["source_id"] == card["source_id"]
        assert "Fixture DC 01" not in json.dumps(upload["data"]["harness_trust"])
        parsed = client.post(f"/api/uploads/{upload['id']}/parse")
        assert parsed.status_code == 200
        preview = client.get(f"/api/uploads/{upload['id']}/preview").json()
        assert preview["harness_trust"]["trusted"] is True

        rejected = client.post(f"/api/uploads/{upload['id']}/merge", json=preview["_review"])
        assert rejected.status_code == 409
        accepted = client.post(f"/api/uploads/{upload['id']}/merge", json={**preview["_review"], "acknowledged": True})
        assert accepted.status_code == 200

    assert len(store.records("asset")) == 1
    assert len(store.records("observation")) == 1
    assert store.records("finding") == []
    with store.connect() as connection:
        row = connection.execute("SELECT status FROM harness_envelopes WHERE envelope_id=?", (envelope["envelope_id"],)).fetchone()
    assert row["status"] == "merged"


def test_server_merges_one_portcast_candidate_observation_and_no_finding(store, monkeypatch):
    key = Ed25519PrivateKey.generate()
    card = portcast_source_card(key)
    enroll_harness_source(store, card, digest(card), "fixture")
    monkeypatch.setattr("workspace.server.run_parser", lambda path, format: parse(path.read_bytes(), format))
    with harness_client(store) as client:
        active_store = client.app.state.store
        uploaded = upload_envelope(client, portcast_envelope(key, card))
        assert uploaded.status_code == 200
        upload = uploaded.json()
        assert client.post(f"/api/uploads/{upload['id']}/parse").status_code == 200
        preview = client.get(f"/api/uploads/{upload['id']}/preview").json()
        assert len(preview["assets"]) == 1
        assert len(preview["observations"]) == 1
        assert client.post(
            f"/api/uploads/{upload['id']}/merge",
            json={**preview["_review"], "acknowledged": True},
        ).status_code == 200

    observations = store.records("observation")
    assert len(store.records("asset")) == 1
    assert len(observations) == 1
    assert observations[0]["data"]["facts"]["result"]["state"] == "candidate"
    assert observations[0]["data"]["facts"]["result"]["vulnerability_assessment"] == "not_performed"
    assert "source_artifact" not in observations[0]["data"]
    assert store.records("finding") == []
    recipient_id = str(uuid.uuid4())
    active_store.configure("peers", [{
        "id": recipient_id,
        "name": "Synthetic Merlin",
        "app": "Merlin",
        "origin": "http://127.0.0.1:8720",
    }])
    transfer = preview_bundle(active_store, [observations[0]["id"]], recipient_id)
    encoded = canonical(transfer)
    assert PORTCAST_REPLAY_ID in encoded
    for forbidden in ("artifact_relpath", ".age", "raw_body", "ciphertext", "CVE-"):
        assert forbidden not in encoded


def test_server_returns_only_a_bounded_harness_trust_preview(store, harness, monkeypatch):
    key, card = harness
    envelope = signed_envelope(key, card)
    monkeypatch.setattr("workspace.server.run_parser", lambda path, format: parse(path.read_bytes(), format))
    with harness_client(store) as client:
        active_store = client.app.state.store
        uploaded = upload_envelope(client, envelope).json()
        parsed = client.post(f"/api/uploads/{uploaded['id']}/parse")
        assert parsed.status_code == 200

        response = client.get(f"/api/evidence/{uploaded['id']}/preview")
        assert response.status_code == 200
        body = response.json()
        summary = json.loads(body["text"])
        assert summary == {
            "kind": "harness_trust_summary_v1",
            "trusted": True,
            "source_id": card["source_id"],
            "key_id": card["key_id"],
            "profile": "cptc11_smb2_security_mode_v1",
            "outcome": "observed",
            "envelope_id": envelope["envelope_id"],
            "signed_sha256": uploaded["data"]["harness_trust"]["signed_sha256"],
            "observation_sha256": uploaded["data"]["harness_trust"]["observation_sha256"],
            "evidence_count": 1,
            "evidence_sha256": ["a" * 64],
            "original_access": "restricted",
        }
        encoded = json.dumps(body)
        assert body["quarantined"] is True
        assert "Fixture DC 01" not in encoded
        assert "dc01.synthetic.test" not in encoded
        assert envelope["signature"]["value"] not in encoded
        assert '"signature"' not in encoded
        assert '"result"' not in encoded

        download = client.get(f"/api/evidence/{uploaded['id']}/download")
        assert download.status_code == 409
        approval = client.post(
            f"/api/evidence/{uploaded['id']}/approve-export",
            json={"base_revision_id": parsed.json()["revision_id"], "artifact_sha256": uploaded["data"]["sha256"]},
        )
        assert approval.status_code == 409
        assert "restricted" in approval.json()["detail"]

    recipient_id = str(uuid.uuid4())
    active_store.configure("peers", [{"id": recipient_id}])
    with pytest.raises(ValueError, match="restricted"):
        preview_bundle(active_store, [uploaded["id"]], recipient_id)
    with pytest.raises(ValueError, match="restricted"):
        build_bundle(active_store, [uploaded["id"]], recipient_id, "fixture")


def concealed_harness_bytes(raw, variant):
    if variant.startswith("escaped_"):
        escaped = "".join(f"\\u{ord(character):04x}" for character in "harness_observation_v1").encode()
        raw = raw.replace(b"harness_observation_v1", escaped)
        variant = variant.removeprefix("escaped_")
    if variant == "bom":
        return b"\xef\xbb\xbf" + raw
    if variant == "oversized":
        return raw + b" " * (MAX_HARNESS_BYTES - len(raw) + 1)
    return raw


@pytest.mark.parametrize("variant", ("canonical", "bom", "oversized", "escaped_bom", "escaped_oversized"))
def test_signed_envelope_cannot_be_hidden_under_an_ordinary_format(store, harness, variant):
    key, card = harness
    raw = concealed_harness_bytes(canonical(signed_envelope(key, card)).encode(), variant)
    assert classify_harness_artifact(raw) == "restricted_harness_envelope"
    artifact = store.root / f"classification-{variant}.json"
    artifact.write_bytes(raw)
    assert classify_harness_artifact_path(artifact) == "restricted_harness_envelope"
    with harness_client(store) as client:
        response = client.post(
            "/api/uploads",
            data={"format": "nmap_text"},
            files={"file": ("scan.txt", raw, "text/plain")},
        )
        assert response.status_code == 422
        assert not store.records("upload")
        assert not list((store.root / "artifacts").iterdir())


@pytest.mark.parametrize("variant", ("canonical", "bom", "oversized", "escaped_bom", "escaped_oversized"))
def test_legacy_mislabeled_envelope_stays_restricted_at_every_egress(store, harness, variant):
    key, card = harness
    raw = concealed_harness_bytes(canonical(signed_envelope(key, card)).encode(), variant)
    upload_id = str(uuid.uuid4())
    artifact = store.root / "artifacts" / upload_id
    artifact.write_bytes(raw)
    artifact.chmod(0o600)
    with store.tx() as connection:
        upload = store.put(
            connection,
            "upload",
            {
                "filename": "legacy.txt",
                "format": "nmap_text",
                "status": "preview",
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
                "artifact_id": upload_id,
                "quarantined": False,
                "limitations": [],
                "reviewed_for_export": True,
            },
            "fixture",
            upload_id,
        )
        store.event(connection, "fixture", "legacy.fixture_created", [upload_id])

    with harness_client(store) as client:
        active_store = client.app.state.store
        preview = client.get(f"/api/evidence/{upload_id}/preview")
        assert preview.status_code == 200
        assert preview.json()["quarantined"] is True
        assert "Fixture DC 01" not in preview.text
        assert client.get(f"/api/evidence/{upload_id}/download").status_code == 409
        approval = client.post(
            f"/api/evidence/{upload_id}/approve-export",
            json={"base_revision_id": upload["revision_id"], "artifact_sha256": hashlib.sha256(raw).hexdigest()},
        )
        assert approval.status_code == 409

    recipient_id = str(uuid.uuid4())
    active_store.configure(
        "peers",
        [{"id": recipient_id, "name": "Synthetic Merlin", "app": "Merlin", "origin": "http://127.0.0.1:8720"}],
    )
    with pytest.raises(ValueError, match="restricted"):
        preview_bundle(active_store, [upload_id], recipient_id)


def test_normalized_harness_observation_transfers_without_the_restricted_original(store, harness, monkeypatch):
    key, card = harness
    monkeypatch.setattr("workspace.server.run_parser", lambda path, format: parse(path.read_bytes(), format))
    with harness_client(store) as client:
        uploaded = upload_envelope(client, signed_envelope(key, card)).json()
        assert client.post(f"/api/uploads/{uploaded['id']}/parse").status_code == 200
        preview = client.get(f"/api/uploads/{uploaded['id']}/preview").json()
        assert client.post(
            f"/api/uploads/{uploaded['id']}/merge",
            json={**preview["_review"], "acknowledged": True},
        ).status_code == 200

        active_store = client.app.state.store
        observation = active_store.records("observation")[0]
        assert "source_artifact" not in observation["data"]
        recipient_id = str(uuid.uuid4())
        active_store.configure(
            "peers",
            [{
                "id": recipient_id,
                "name": "Synthetic Merlin",
                "app": "Merlin",
                "origin": "http://127.0.0.1:8720",
            }],
        )
        transfer = preview_bundle(active_store, [observation["id"]], recipient_id)
        assert {record["kind"] for record in transfer["records"]} == {"asset", "observation"}
        assert transfer["files"] == []


def test_server_replay_rules_and_safe_audit(store, harness):
    key, card = harness
    first = signed_envelope(key, card)
    with harness_client(store) as client:
        accepted = upload_envelope(client, first)
        assert accepted.status_code == 200
        assert upload_envelope(client, first).json()["id"] == accepted.json()["id"]

        envelope_reuse = signed_envelope(key, card, envelope_id=first["envelope_id"])
        assert upload_envelope(client, envelope_reuse).status_code == 409
        observation_reuse = signed_envelope(key, card, observation_id=first["observation"]["observation_id"])
        assert upload_envelope(client, observation_reuse).status_code == 409

    audit = (store.root / "audit.jsonl").read_text()
    assert "Fixture DC 01" not in audit
    assert "dc01.synthetic.test" not in audit
    assert first["envelope_id"] in audit


def test_revocation_after_preview_blocks_merge(store, harness, monkeypatch):
    key, card = harness
    monkeypatch.setattr("workspace.server.run_parser", lambda path, format: parse(path.read_bytes(), format))
    with harness_client(store) as client:
        upload = upload_envelope(client, signed_envelope(key, card)).json()
        client.post(f"/api/uploads/{upload['id']}/parse")
        preview = client.get(f"/api/uploads/{upload['id']}/preview").json()
        revoke_harness_source(client.app.state.store, card["source_id"], "fixture")
        response = client.post(f"/api/uploads/{upload['id']}/merge", json={**preview["_review"], "acknowledged": True})
    assert response.status_code == 409
    assert store.records("asset") == []


def test_transfer_validation_rejects_the_restricted_harness_original(store, harness):
    key, card = harness
    trust = verify_harness_observation(store, canonical(signed_envelope(key, card)).encode())
    upload = {
        "filename": "reviewed.json", "format": "harness_observation_v1", "status": "preview",
        "sha256": "d" * 64, "size": 1024, "artifact_id": str(uuid.uuid4()), "quarantined": False,
        "limitations": [], "reviewed_for_export": True, "harness_trust": trust,
    }
    with pytest.raises(ValueError):
        validate_record_data("upload", upload)


def test_transfer_revalidates_smb_attestation_timestamps_and_media_type(harness):
    key, card = harness
    parsed = parse(canonical(signed_envelope(key, card)).encode(), "harness_observation_v1")
    valid = copy.deepcopy(parsed["observations"][0])
    valid["subject"] = str(uuid.uuid4())
    validate_record_data("observation", valid)

    mutations = []
    malformed_time = copy.deepcopy(valid)
    malformed_time["facts"]["harness_attestation"]["reviewed_at"] = "garbage"
    mutations.append(malformed_time)
    wrong_order = copy.deepcopy(valid)
    wrong_order["facts"]["harness_attestation"]["observed_at"] = "2026-09-09T12:00:00.000000Z"
    mutations.append(wrong_order)
    malformed_media = copy.deepcopy(valid)
    malformed_media["facts"]["evidence_refs"][0]["media_type"] = {}
    mutations.append(malformed_media)

    for value in mutations:
        with pytest.raises(ValueError):
            validate_record_data("observation", value)


def test_transfer_rejects_harness_contract_hash_drift(harness, monkeypatch):
    key, card = harness
    parsed = parse(canonical(signed_envelope(key, card)).encode(), "harness_observation_v1")
    observation = copy.deepcopy(parsed["observations"][0])
    observation["subject"] = str(uuid.uuid4())
    monkeypatch.setattr(transfer_module, "HARNESS_CONTRACT_SHA256", "0" * 64)

    with pytest.raises(ValueError, match="contract hash"):
        validate_record_data("observation", observation)


def test_transfer_checks_contract_hash_when_smb_evidence_is_empty(harness, monkeypatch):
    key, card = harness
    envelope = signed_envelope(key, card)
    envelope["observation"]["evidence_refs"] = []
    parsed = parse(canonical(resign(key, envelope)).encode(), "harness_observation_v1")
    observation = copy.deepcopy(parsed["observations"][0])
    observation["subject"] = str(uuid.uuid4())
    monkeypatch.setattr(transfer_module, "HARNESS_CONTRACT_SHA256", "0" * 64)

    with pytest.raises(ValueError, match="contract hash"):
        validate_record_data("observation", observation)


@pytest.mark.skipif(not shutil.which("bwrap"), reason="bubblewrap is required for the contained parser")
def test_harness_contract_is_available_inside_contained_parser(tmp_path, harness):
    key, card = harness
    source = tmp_path / "fixture.json"
    source.write_bytes(canonical(signed_envelope(key, card)).encode())
    result = run_parser(source, "harness_observation_v1")
    assert result["complete"] is True
    assert result["observations"][0]["facts"]["result"]["security_mode"] == "signing_required"
