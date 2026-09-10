"""Shape-only normalization for reviewed harness observations.

Source enrollment and signature verification stay outside the contained parser.
"""
from ..common import parse_harness_json, validate_harness_envelope


def _summary(envelope):
    observation = envelope["observation"]
    profile = envelope["profile"]["name"]
    if profile == "cptc11_smb2_security_mode_v1":
        return f"SMB2 security mode: {observation['result']['security_mode']}"
    if profile == "web.http_jellyfin_public_identity":
        result = observation["result"]
        return f"{result['product']} {result['version']} public identity ({result['state']})"
    raise ValueError("Unsupported reviewed harness profile")


def parse(raw, _format, context):
    envelope = validate_harness_envelope(parse_harness_json(raw))
    observation = envelope["observation"]
    asset = observation["asset"]
    asset_id = context.asset(
        asset["asset_key"], asset["label"], asset["kind"], asset["track"],
        asset_key=asset["asset_key"], identifiers=asset["identifiers"], context=asset["context"],
    )
    attestation = {
        "schema": "harness_observation_v1",
        "envelope_id": envelope["envelope_id"],
        "observation_id": observation["observation_id"],
        "source_id": envelope["producer"]["source_id"],
        "key_id": envelope["producer"]["key_id"],
        "profile": envelope["profile"]["name"],
        "review_id": envelope["review"]["review_id"],
        "reviewed_at": envelope["review"]["reviewed_at"],
        "observed_at": observation["observed_at"],
    }
    if envelope["profile"]["name"] == "web.http_jellyfin_public_identity":
        attestation["execution"] = envelope["execution"]
    context.observed(
        asset_id,
        _summary(envelope),
        "reviewed harness observation",
        outcome=observation["outcome"], detector=observation["detector"], result=observation["result"],
        evidence_refs=observation["evidence_refs"], harness_attestation=attestation,
    )
    if observation["outcome"] not in ("observed", "not_observed"):
        context.result["limitations"].append(
            f"The reviewed harness outcome is {observation['outcome']}; treat this observation as incomplete."
        )


__all__ = ["parse"]
