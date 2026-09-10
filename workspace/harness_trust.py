"""Enrollment and host-side verification for reviewed harness observations."""
import base64
import hashlib
import json
from pathlib import Path
import re
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .store import canonical, digest, utc
from .parsers.common.harness_validation import (
    CLOCK_FUTURE_TOLERANCE,
    HARNESS_CONTRACT_SHA256,
    MAX_HARNESS_BYTES,
    PORTCAST_PROFILE,
    PORTCAST_REPLAY_NAMESPACE,
    SMB_PROFILE,
    harness_contract_path,
    parse_harness_json,
    portcast_replay_id,
    validate_harness_envelope,
)


PROFILE = SMB_PROFILE
PROFILES = (SMB_PROFILE, PORTCAST_PROFILE)
PORTCAST_PIN_FIELDS = frozenset({
    "source_engagement_id", "policy_sha256", "release_sha256", "module_sha256",
    "parser_sha256", "catalog_sha256", "profile_sha256", "operation_sha256",
    "worker_sha256", "runtime_pinset_sha256",
})
PORTCAST_FIXED_PINS = {
    "catalog_sha256": "d37bc4a0ba5368e02306f52cce5927d5a5db6e7dee90dda0cc0ee3d243e66113",
    "profile_sha256": "2acbea838777e029076eb93eb039170f806713d3c8fe9724dacb7827ed2322a3",
    "operation_sha256": "e60c94321ac232504c22b1d55e9702a2526f9a0022284b6d9ef7b2c980943fe6",
    "worker_sha256": "472620e6112b00882f480ea4a0209e8dcdab9e0c54ba98ae2bef86c07342f400",
    "runtime_pinset_sha256": "9bcaeaa02a0c9f52b1b32c4259a35043b9dd0caec55f6fec150ec6f5a722df16",
}
ORDINARY_ARTIFACT = "ordinary_evidence"
RESTRICTED_HARNESS_ARTIFACT = "restricted_harness_envelope"
CONTRACT_PATH = harness_contract_path()
HARNESS_KIND_MARKER = b"harness_observation_v1"
HARNESS_KIND_PATTERN = re.compile(
    b"".join(
        b"(?:" + re.escape(bytes((character,))) + b"|\\\\u" + f"{character:04x}".encode("ascii") + b")"
        for character in HARNESS_KIND_MARKER
    ),
    re.IGNORECASE,
)
HARNESS_KIND_PATTERN_OVERLAP = len(HARNESS_KIND_MARKER) * 6 - 1


def classify_harness_artifact(raw):
    """Classify content conservatively, without trusting its UI label."""
    if isinstance(raw, (bytes, bytearray, memoryview)) and HARNESS_KIND_PATTERN.search(bytes(raw)):
        return RESTRICTED_HARNESS_ARTIFACT
    try:
        value = parse_harness_json(raw)
    except ValueError:
        return ORDINARY_ARTIFACT
    if value.get("kind") == "harness_observation_v1":
        return RESTRICTED_HARNESS_ARTIFACT
    return ORDINARY_ARTIFACT


def classify_harness_artifact_path(path):
    """Classify a bounded upload without loading large ordinary evidence at once."""
    path = Path(path)
    size = path.stat().st_size
    collected = bytearray() if size <= MAX_HARNESS_BYTES else None
    overlap = b""
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            if HARNESS_KIND_PATTERN.search(overlap + chunk):
                return RESTRICTED_HARNESS_ARTIFACT
            overlap = (overlap + chunk)[-HARNESS_KIND_PATTERN_OVERLAP:]
            if collected is not None:
                collected.extend(chunk)
    return classify_harness_artifact(bytes(collected)) if collected is not None else ORDINARY_ARTIFACT


def _portcast_envelope_pins(value):
    execution = value["execution"]
    target = execution["target_profile"]
    return {
        "source_engagement_id": execution["source_engagement_id"],
        "policy_sha256": execution["policy"]["sha256"],
        "release_sha256": execution["release"]["sha256"],
        "module_sha256": execution["module"]["sha256"],
        "parser_sha256": execution["parser"]["sha256"],
        "catalog_sha256": target["catalog_sha256"],
        "profile_sha256": target["profile_sha256"],
        "operation_sha256": target["operation_sha256"],
        "worker_sha256": execution["collector"]["worker_sha256"],
        "runtime_pinset_sha256": target["runtime_pinset_sha256"],
    }


def validate_harness_source_card(card):
    required = {"schema_version", "kind", "source_id", "name", "engagement_id", "role", "key_id", "algorithm", "public_key", "profiles"}
    if not isinstance(card, dict) or not required.issubset(card) or set(card) - required - {"profile_pins"} or card.get("schema_version") != 1 or card.get("kind") != "harness_source":
        raise ValueError("Unsupported harness source card")
    try:
        uuid.UUID(card["source_id"]); uuid.UUID(card["engagement_id"])
        key = base64.b64decode(card["public_key"], validate=True)
    except Exception as error:
        raise ValueError("Harness source identity or key is invalid") from error
    if (card["role"] != "reviewed_broker" or card["algorithm"] != "Ed25519" or len(key) != 32
            or not isinstance(card["name"], str) or not 1 <= len(card["name"]) <= 200
            or not isinstance(card["key_id"], str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", card["key_id"])
            or card["profiles"] not in ([SMB_PROFILE], [PORTCAST_PROFILE], list(PROFILES))):
        raise ValueError("Harness source card is outside the admitted profile")
    if PORTCAST_PROFILE in card["profiles"]:
        profile_pins = card.get("profile_pins")
        pins = profile_pins.get(PORTCAST_PROFILE) if isinstance(profile_pins, dict) and set(profile_pins) == {PORTCAST_PROFILE} else None
        if not isinstance(pins, dict) or set(pins) != PORTCAST_PIN_FIELDS:
            raise ValueError("PortCast source card requires exact provenance pins")
        if (not isinstance(pins["source_engagement_id"], str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", pins["source_engagement_id"])
                or any(not isinstance(pins[field], str) or not re.fullmatch(r"[0-9a-f]{64}", pins[field])
                       for field in PORTCAST_PIN_FIELDS - {"source_engagement_id"})
                or any(pins[field] != expected for field, expected in PORTCAST_FIXED_PINS.items())):
            raise ValueError("PortCast source card has invalid provenance pins")
    elif "profile_pins" in card:
        raise ValueError("SMB-only source cards do not use provenance pins")
    return card


def enroll_harness_source(store, card, fingerprint, actor="operator"):
    validate_harness_source_card(card)
    config = store.setting("config")
    if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint) or digest(card) != fingerprint:
        raise ValueError("Harness source fingerprint does not match")
    if card["engagement_id"] != config["engagement"]["id"]:
        raise ValueError("Harness source engagement does not match")
    encoded = canonical(card)
    with store.tx() as connection:
        current = connection.execute("SELECT * FROM harness_sources WHERE source_id=?", (card["source_id"],)).fetchone()
        if current:
            if current["card"] == encoded and current["fingerprint"] == fingerprint:
                return dict(current)
            raise ValueError("Harness source identity changed; enroll rotation with a new source identifier")
        enrolled_at = utc()
        connection.execute(
            "INSERT INTO harness_sources(source_id,card,fingerprint,status,enrolled_at,revoked_at) VALUES(?,?,?,?,?,NULL)",
            (card["source_id"], encoded, fingerprint, "active", enrolled_at),
        )
        store.event(connection, actor, "harness.source_enrolled", [card["source_id"]], key_id=card["key_id"], fingerprint=fingerprint, profiles=card["profiles"])
        return {"source_id": card["source_id"], "card": encoded, "fingerprint": fingerprint, "status": "active", "enrolled_at": enrolled_at, "revoked_at": None}


def revoke_harness_source(store, source_id, actor="operator"):
    with store.tx() as connection:
        row = connection.execute("SELECT * FROM harness_sources WHERE source_id=?", (source_id,)).fetchone()
        if not row:
            raise ValueError("Harness source is not enrolled")
        if row["status"] == "revoked":
            return dict(row)
        revoked_at = utc()
        connection.execute("UPDATE harness_sources SET status='revoked',revoked_at=? WHERE source_id=?", (revoked_at, source_id))
        store.event(connection, actor, "harness.source_revoked", [source_id])
        return {**dict(row), "status": "revoked", "revoked_at": revoked_at}


def verify_harness_observation(store, raw):
    value = validate_harness_envelope(parse_harness_json(raw))
    producer = value["producer"]
    with store.connect() as connection:
        row = connection.execute("SELECT * FROM harness_sources WHERE source_id=?", (producer["source_id"],)).fetchone()
    if not row or row["status"] != "active":
        raise ValueError("Harness source is not active")
    card = validate_harness_source_card(json.loads(row["card"]))
    config = store.setting("config")
    if value["engagement_id"] != config["engagement"]["id"] or card["engagement_id"] != value["engagement_id"]:
        raise ValueError("Harness engagement does not match")
    if (producer["role"] != card["role"] or producer["key_id"] != card["key_id"]
            or value["signature"]["key_id"] != card["key_id"] or value["profile"]["name"] not in card["profiles"]):
        raise ValueError("Harness source, key, or profile binding does not match")
    if value["profile"]["name"] == PORTCAST_PROFILE:
        enrolled_pins = card["profile_pins"][PORTCAST_PROFILE]
        if _portcast_envelope_pins(value) != enrolled_pins:
            raise ValueError("PortCast envelope provenance pins do not match the enrolled source")
    unsigned = {key: item for key, item in value.items() if key != "signature"}
    try:
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(card["public_key"], validate=True))
        public.verify(base64.b64decode(value["signature"]["value"], validate=True), canonical(unsigned).encode())
    except (InvalidSignature, ValueError) as error:
        raise ValueError("Harness signature verification failed") from error
    observation = value["observation"]
    return {
        "trusted": True,
        "source_id": producer["source_id"],
        "key_id": producer["key_id"],
        "profile": value["profile"]["name"],
        "outcome": observation["outcome"],
        "envelope_id": value["envelope_id"],
        "observation_id": observation["observation_id"],
        "signed_sha256": hashlib.sha256(canonical(unsigned).encode()).hexdigest(),
        "observation_sha256": hashlib.sha256(canonical(observation).encode()).hexdigest(),
        "evidence_count": len(observation["evidence_refs"]),
        "evidence_sha256": [item["sha256"] for item in observation["evidence_refs"]],
    }


__all__ = ["CLOCK_FUTURE_TOLERANCE", "HARNESS_CONTRACT_SHA256", "MAX_HARNESS_BYTES", "ORDINARY_ARTIFACT", "PORTCAST_PROFILE", "PORTCAST_REPLAY_NAMESPACE", "PROFILE", "RESTRICTED_HARNESS_ARTIFACT", "SMB_PROFILE", "classify_harness_artifact", "classify_harness_artifact_path", "enroll_harness_source", "parse_harness_json", "portcast_replay_id", "revoke_harness_source", "validate_harness_envelope", "validate_harness_source_card", "verify_harness_observation"]
