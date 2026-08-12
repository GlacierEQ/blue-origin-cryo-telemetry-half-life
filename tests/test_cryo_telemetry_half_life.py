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
        "evidence_digest": "d" * 64,
    }


def _evaluate(payload=None, budget=4.0):
    return CryoTelemetryHalfLife().evaluate(
        CryoTelemetryHalfLifeRequest("sim-command-1", payload or _payload(), budget=budget)
    )


def test_fresh_telemetry_and_independent_keys_allow():
    receipt = _evaluate()
    assert receipt.decision is Decision.ALLOW
    assert receipt.result["eligible"] is True
    assert receipt.reasons == ("fresh_telemetry_and_dual_key_verified",)
    assert receipt.metrics["distinct_principals"] == 2
    assert receipt.metrics["distinct_keys"] == 2
    assert receipt.metrics["min_observed_freshness"] >= 0.5
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


def test_same_principal_cannot_satisfy_dual_key():
    payload = _payload()
    payload["approvals"][1]["principal"] = "operator-a"
    receipt = _evaluate(payload)
    assert receipt.decision is Decision.REFUSE
    assert "dual_key_requires_distinct_principals" in receipt.reasons


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


def test_work_budget_is_enforced():
    receipt = _evaluate(budget=1.05)
    assert receipt.decision is Decision.REFUSE
    assert "work_budget_exceeded" in receipt.reasons


def test_same_request_is_deterministic():
    engine = CryoTelemetryHalfLife()
    request = CryoTelemetryHalfLifeRequest("sim-command-1", _payload(), budget=4.0)
    assert engine.evaluate(request) == engine.evaluate(request)
