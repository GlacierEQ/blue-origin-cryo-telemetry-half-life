from copy import deepcopy

from cryo_telemetry_half_life import Decision, CryoTelemetryHalfLife, CryoTelemetryHalfLifeRequest


def _payload() -> dict:
    return {
        "now": 1000.0,
        "command": {"name": "simulation-stage-transition", "mode": "simulation"},
        "required_channels": ["tank.pressure", "tank.temperature"],
        "min_freshness": 0.5,
        "telemetry": [
            {"channel": "tank.pressure", "observed_at": 995.0, "half_life_s": 20.0, "quality": 1.0, "value": 42.0},
            {"channel": "tank.temperature", "observed_at": 996.0, "half_life_s": 20.0, "quality": 0.95, "value": 90.0},
        ],
        "required_roles": ["operator", "safety"],
        "approval_ttl_s": 30.0,
        "approvals": [
            {"key_id": "key-op", "principal": "operator-a", "role": "operator", "approved_at": 997.0},
            {"key_id": "key-safe", "principal": "safety-b", "role": "safety", "approved_at": 998.0},
        ],
    }


def _evaluate(payload=None, budget=4.0, **request_fields):
    return CryoTelemetryHalfLife().evaluate(
        CryoTelemetryHalfLifeRequest(
            "sim-command-1",
            payload or _payload(),
            budget=budget,
            **request_fields,
        )
    )


def test_fresh_telemetry_and_independent_keys_allow():
    receipt = _evaluate()
    assert receipt.decision is Decision.ALLOW
    assert receipt.result["eligible"] is True
    assert receipt.reasons == ("fresh_telemetry_and_independent_approvals_verified",)
    assert receipt.metrics["distinct_principals"] == 2
    assert receipt.metrics["distinct_keys"] == 2
    assert receipt.metrics["selected_approval_count"] == 2
    assert {item["role"] for item in receipt.result["selected_approvals"]} == {"operator", "safety"}
    assert receipt.metrics["min_observed_freshness"] >= 0.5
    assert len(receipt.result["evidence_digest"]) == 64
    assert len(receipt.digest) == 64


def test_stale_required_telemetry_refuses():
    payload = _payload()
    payload["telemetry"][0] = {"channel": "tank.pressure", "observed_at": 900.0, "half_life_s": 20.0, "quality": 1.0}
    receipt = _evaluate(payload)
    assert receipt.decision is Decision.REFUSE
    assert "telemetry_tank.pressure_stale" in receipt.reasons


def test_missing_required_channel_refuses():
    payload = _payload()
    payload["telemetry"] = [payload["telemetry"][0]]
    receipt = _evaluate(payload)
    assert receipt.decision is Decision.REFUSE
    assert "telemetry_tank.temperature_missing" in receipt.reasons


def test_low_quality_can_make_recent_sample_stale():
    payload = _payload()
    payload["telemetry"][0]["quality"] = 0.2
    receipt = _evaluate(payload)
    assert receipt.decision is Decision.REFUSE
    assert "telemetry_tank.pressure_stale" in receipt.reasons


def test_same_principal_cannot_satisfy_required_roles():
    payload = _payload()
    payload["approvals"][1]["principal"] = "operator-a"
    receipt = _evaluate(payload)
    assert receipt.decision is Decision.REFUSE
    assert "dual_key_requires_distinct_principals" in receipt.reasons
    assert "required_role_approvals_not_independent" in receipt.reasons


def test_unrelated_role_cannot_mask_required_role_principal_reuse():
    payload = _payload()
    payload["approvals"][1]["principal"] = "operator-a"
    payload["approvals"].append(
        {"key_id": "observer-key", "principal": "observer-b", "role": "observer", "approved_at": 999.0}
    )
    receipt = _evaluate(payload)
    assert receipt.decision is Decision.REFUSE
    assert "dual_key_requires_distinct_principals" in receipt.reasons
    assert "required_role_approvals_not_independent" in receipt.reasons


def test_valid_independent_combination_is_selected_when_extra_approvals_exist():
    payload = _payload()
    payload["approvals"] = [
        {"key_id": "op-a", "principal": "person-a", "role": "operator", "approved_at": 997.0},
        {"key_id": "safe-a", "principal": "person-a", "role": "safety", "approved_at": 997.5},
        {"key_id": "safe-b", "principal": "person-b", "role": "safety", "approved_at": 998.0},
    ]
    receipt = _evaluate(payload)
    assert receipt.decision is Decision.ALLOW
    selected = receipt.result["selected_approvals"]
    assert len({item["principal"] for item in selected}) == 2
    assert len({item["key_id"] for item in selected}) == 2


def test_duplicate_key_refuses():
    payload = _payload()
    payload["approvals"][1]["key_id"] = "key-op"
    receipt = _evaluate(payload)
    assert receipt.decision is Decision.REFUSE
    assert "approval_key-op_duplicate_key" in receipt.reasons
    assert "approval_role_safety_missing" in receipt.reasons


def test_expired_approval_refuses():
    payload = _payload()
    payload["approvals"][1]["approved_at"] = 900.0
    receipt = _evaluate(payload)
    assert receipt.decision is Decision.REFUSE
    assert "approval_key-safe_expired" in receipt.reasons
    assert "approval_role_safety_missing" in receipt.reasons


def test_future_telemetry_refuses():
    payload = _payload()
    payload["telemetry"][0]["observed_at"] = 1001.0
    receipt = _evaluate(payload)
    assert receipt.decision is Decision.REFUSE
    assert "telemetry_tank.pressure_from_future" in receipt.reasons


def test_required_role_must_be_present():
    payload = _payload()
    payload["required_roles"] = ["operator", "safety", "test-director"]
    receipt = _evaluate(payload)
    assert receipt.decision is Decision.REFUSE
    assert "approval_role_test-director_missing" in receipt.reasons


def test_identity_fields_are_not_string_coerced():
    malformed_cases = [
        ("telemetry", 0, "channel", 123, "telemetry_0_channel_type_invalid"),
        ("approvals", 0, "key_id", True, "approval_0_key_id_type_invalid"),
        ("approvals", 0, "principal", 123, "approval_0_principal_type_invalid"),
        ("approvals", 0, "role", False, "approval_0_role_type_invalid"),
    ]
    for collection, index, field, value, expected in malformed_cases:
        payload = _payload()
        payload[collection][index][field] = value
        receipt = _evaluate(payload)
        assert receipt.decision is Decision.REFUSE
        assert expected in receipt.reasons


def test_expected_evidence_digest_binds_normalized_evidence():
    baseline = _evaluate()
    assert baseline.decision is Decision.ALLOW
    expected = baseline.result["evidence_digest"]

    payload = _payload()
    payload["evidence_digest"] = expected
    verified = _evaluate(payload)
    assert verified.decision is Decision.ALLOW
    assert verified.metrics["evidence_digest_verified"] is True

    changed = deepcopy(payload)
    changed["telemetry"][0]["value"] = 43.0
    refused = _evaluate(changed)
    assert refused.decision is Decision.REFUSE
    assert "evidence_digest_mismatch" in refused.reasons


def test_arbitrary_evidence_digest_is_refused():
    payload = _payload()
    payload["evidence_digest"] = "d" * 64
    receipt = _evaluate(payload)
    assert receipt.decision is Decision.REFUSE
    assert "evidence_digest_mismatch" in receipt.reasons


def test_request_expiry_is_enforced_against_evaluation_time():
    receipt = _evaluate(not_after=999.0)
    assert receipt.decision is Decision.REFUSE
    assert "request_expired" in receipt.reasons


def test_grant_id_type_is_validated():
    receipt = _evaluate(grant_id=123)
    assert receipt.decision is Decision.REFUSE
    assert "grant_id_type_invalid" in receipt.reasons


def test_work_budget_is_enforced_before_collection_normalization():
    payload = _payload()
    payload["telemetry"] = payload["telemetry"] * 20
    receipt = _evaluate(payload, budget=1.1)
    assert receipt.decision is Decision.REFUSE
    assert "work_budget_exceeded" in receipt.reasons
    assert receipt.metrics["telemetry_count"] == 0


def test_collection_limits_fail_closed_before_iteration():
    payload = _payload()
    payload["telemetry"] = [payload["telemetry"][0]] * (CryoTelemetryHalfLife.MAX_TELEMETRY + 1)
    receipt = _evaluate(payload, budget=100.0)
    assert receipt.decision is Decision.REFUSE
    assert "telemetry_over_limit" in receipt.reasons


def test_same_request_is_deterministic():
    engine = CryoTelemetryHalfLife()
    request = CryoTelemetryHalfLifeRequest("sim-command-1", _payload(), budget=4.0)
    assert engine.evaluate(request) == engine.evaluate(request)
