"""Pure, shared validation for reviewed harness observation envelopes.

The web process and the contained parser import this exact module. It performs
no I/O except reading the pinned local JSON Schema and opens no network or
target-facing capability.
"""
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import uuid

from jsonschema import Draft202012Validator, FormatChecker


MAX_HARNESS_BYTES = 4 * 1024**2
MAX_JSON_DEPTH = 16
MAX_DECLARED_EVIDENCE_BYTES = 256 * 1024**2
CLOCK_FUTURE_TOLERANCE = timedelta(minutes=5)
SMB_PROFILE = "cptc11_smb2_security_mode_v1"
PORTCAST_PROFILE = "web.http_jellyfin_public_identity"
PORTCAST_REPLAY_NAMESPACE = uuid.UUID("2d9c186e-308b-5b02-8bf1-d9c1ebea2874")
HARNESS_CONTRACT_SHA256 = "37823340c1a815439667d8eb0d64eb1e2fbda4e74ab54aa27e9745e2cdaf4f5b"


def harness_contract_path():
    here = Path(__file__).resolve()
    root = here.parents[3] if (here.parents[3] / "contracts").is_dir() else here.parents[2]
    return root / "contracts" / "harness-observation-v1.schema.json"


def _pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError("Harness JSON contains a duplicate object key")
        result[key] = value
    return result


def _reject_constant(_):
    raise ValueError("Harness JSON contains a non-finite number")


def _depth(value, level=1):
    if level > MAX_JSON_DEPTH:
        raise ValueError("Harness JSON nesting exceeds its limit")
    for child in value.values() if isinstance(value, dict) else value if isinstance(value, list) else ():
        _depth(child, level + 1)


def parse_harness_json(raw):
    """Decode one unambiguous, bounded JSON document."""
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_HARNESS_BYTES or raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("Harness JSON is empty, encoded with a BOM, or exceeds 4 MiB")
    try:
        text = raw.decode("utf-8", "strict")
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_reject_constant)
    except RecursionError as error:
        raise ValueError("Harness JSON nesting exceeds its limit") from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Harness JSON must be one strict UTF-8 document") from error
    if not isinstance(value, dict):
        raise ValueError("Harness envelope must be an object")
    _depth(value)
    return value


def load_harness_schema():
    path = harness_contract_path()
    raw = path.read_bytes()
    expected = (path.parent / "HARNESS_CONTRACT_SHA256").read_text().strip()
    if expected != HARNESS_CONTRACT_SHA256 or hashlib.sha256(raw).hexdigest() != HARNESS_CONTRACT_SHA256:
        raise ValueError("Harness contract hash does not match this release")
    value = json.loads(raw)
    Draft202012Validator.check_schema(value)
    return value


def parse_harness_timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", value):
        raise ValueError("Harness timestamps must use RFC3339 UTC with microseconds")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.utcoffset() != timezone.utc.utcoffset(None):
        raise ValueError("Harness timestamp is not UTC")
    return parsed


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def portcast_replay_id(value):
    execution = value["execution"]
    observation = value["observation"]
    name = {
        "schema": "harbinger.portcast.replay.v1",
        "source_engagement_id": execution["source_engagement_id"],
        "policy_sha256": execution["policy"]["sha256"],
        "release_sha256": execution["release"]["sha256"],
        "frozen_plan_id": execution["frozen_plan"]["id"],
        "frozen_plan_sha256": execution["frozen_plan"]["sha256"],
        "action_id": execution["action_id"],
        "profile_id": value["profile"]["name"],
        "target_id": execution["target_profile"]["target_id"],
        "check_id": observation["result"]["check_id"],
        "evidence_sha256": observation["evidence_refs"][0]["sha256"],
    }
    return str(uuid.uuid5(PORTCAST_REPLAY_NAMESPACE, _canonical(name)))


def validate_harness_envelope(value):
    """Apply the exact schema and cross-field rules at every process boundary."""
    try:
        Draft202012Validator(load_harness_schema(), format_checker=FormatChecker()).validate(value)
        issued_at = parse_harness_timestamp(value["issued_at"])
        reviewed_at = parse_harness_timestamp(value["review"]["reviewed_at"])
        observed_at = parse_harness_timestamp(value["observation"]["observed_at"])
        if not observed_at <= reviewed_at <= issued_at:
            raise ValueError("Harness timestamps are outside their required order")
        if any(item > datetime.now(timezone.utc) + CLOCK_FUTURE_TOLERANCE for item in (issued_at, reviewed_at, observed_at)):
            raise ValueError("Harness timestamp is too far in the future")
        execution = value["execution"]
        if (execution["target_profile"]["id"] != value["profile"]["name"]
                or execution["target_profile"]["version"] != value["profile"]["version"]):
            raise ValueError("Harness target profile binding does not match")
        reserved = execution["reservation"]["reserved"]
        consumed = execution["reservation"]["consumed"]
        if any(consumed[field] > reserved[field] for field in reserved):
            raise ValueError("Harness resource consumption exceeds its reservation")
        if value["profile"]["name"] == PORTCAST_PROFILE:
            evidence = value["observation"]["evidence_refs"][0]
            if consumed["rx_bytes"] != consumed["capture_bytes"] or consumed["capture_bytes"] != evidence["size"]:
                raise ValueError("PortCast wire receipt and evidence metadata differ")
            if value["observation"]["observation_id"] != portcast_replay_id(value):
                raise ValueError("PortCast observation replay identity differs")
        if sum(ref["size"] for ref in value["observation"]["evidence_refs"]) > MAX_DECLARED_EVIDENCE_BYTES:
            raise ValueError("Declared evidence exceeds the aggregate limit")
        signature = base64.b64decode(value["signature"]["value"], validate=True)
        if len(signature) != 64:
            raise ValueError("Harness signature length is invalid")
    except ValueError:
        raise
    except Exception as error:
        raise ValueError("Harness envelope does not satisfy the versioned contract") from error
    return value


__all__ = [
    "CLOCK_FUTURE_TOLERANCE",
    "HARNESS_CONTRACT_SHA256",
    "MAX_DECLARED_EVIDENCE_BYTES",
    "MAX_HARNESS_BYTES",
    "MAX_JSON_DEPTH",
    "PORTCAST_PROFILE",
    "PORTCAST_REPLAY_NAMESPACE",
    "SMB_PROFILE",
    "harness_contract_path",
    "load_harness_schema",
    "parse_harness_json",
    "parse_harness_timestamp",
    "portcast_replay_id",
    "validate_harness_envelope",
]
