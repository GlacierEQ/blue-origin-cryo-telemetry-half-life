from __future__ import annotations

from cryo_telemetry_half_life import CryoTelemetryHalfLife, CryoTelemetryHalfLifeRequest, Decision


def telemetry(now=100.0, pressure_at=90.0, temp_at=95.0, pressure_healthy=True):
    return [
        {"channel":"tank_pressure","value":42.0,"unit":"psi","observed_at":pressure_at,"half_life_s":30.0,"healthy":pressure_healthy},
        {"channel":"line_temp","value":-180.0,"unit":"C","observed_at":temp_at,"half_life_s":20.0,"healthy":True},
    ]


def payload_with_approvals(*, now=100.0, tel=None):
    base={"now":now,"scope":"valve.actuate","required_channels":["tank_pressure","line_temp"],"telemetry":tel or telemetry(now),"approvals":[],"min_authority_keys":2,"max_approval_age_s":30.0}
    probe=CryoTelemetryHalfLife().evaluate(CryoTelemetryHalfLifeRequest("cryo-a",base,1.0))
    digest=probe.metrics["result"]["telemetry_digest"]
    base["approvals"]=[
        {"authority_id":"flight","authority_group":"flight-safety","approved_at":98.0,"expires_at":120.0,"scopes":["valve.actuate"],"telemetry_digest":digest},
        {"authority_id":"test","authority_group":"test-ops","approved_at":99.0,"expires_at":120.0,"scopes":["valve.actuate"],"telemetry_digest":digest},
    ]
    return base


def evaluate(payload):
    return CryoTelemetryHalfLife().evaluate(CryoTelemetryHalfLifeRequest("cryo-a",payload,1.0))


def test_fresh_telemetry_with_independent_dual_key_allows_actuation() -> None:
    receipt=evaluate(payload_with_approvals())
    assert receipt.decision is Decision.ALLOW
    assert receipt.metrics["result"]["authorized"] is True
    assert len(receipt.metrics["result"]["accepted_authorities"]) == 2


def test_required_channel_past_half_life_refuses() -> None:
    p=payload_with_approvals(tel=telemetry(100.0,pressure_at=60.0))
    receipt=evaluate(p)
    assert receipt.decision is Decision.REFUSE
    assert "required_telemetry_past_half_life_or_unhealthy" in receipt.reasons
    assert "tank_pressure" in receipt.metrics["result"]["stale_or_unhealthy"]


def test_unhealthy_required_channel_refuses_even_when_fresh() -> None:
    p=payload_with_approvals(tel=telemetry(100.0,pressure_healthy=False))
    receipt=evaluate(p)
    assert receipt.decision is Decision.REFUSE
    assert "required_telemetry_past_half_life_or_unhealthy" in receipt.reasons


def test_missing_required_telemetry_refuses() -> None:
    p=payload_with_approvals(); p["required_channels"].append("flow_rate")
    receipt=evaluate(p)
    assert receipt.decision is Decision.REFUSE
    assert "required_telemetry_missing" in receipt.reasons


def test_single_authority_is_not_dual_key() -> None:
    p=payload_with_approvals(); p["approvals"]=p["approvals"][:1]
    receipt=evaluate(p)
    assert receipt.decision is Decision.REFUSE
    assert "dual_key_approval_missing" in receipt.reasons


def test_same_authority_group_cannot_fake_independence() -> None:
    p=payload_with_approvals(); p["approvals"][1]["authority_group"]="flight-safety"
    receipt=evaluate(p)
    assert receipt.decision is Decision.REFUSE
    assert "independent_authority_groups_missing" in receipt.reasons


def test_approval_is_bound_to_exact_telemetry_snapshot() -> None:
    p=payload_with_approvals(); p["approvals"][0]["telemetry_digest"]="0"*64
    receipt=evaluate(p)
    assert receipt.decision is Decision.REFUSE
    assert any(r.startswith("approval_telemetry_mismatch:flight") for r in receipt.reasons)


def test_old_approval_refuses_even_with_fresh_telemetry() -> None:
    p=payload_with_approvals(); p["approvals"][0]["approved_at"]=50.0
    receipt=evaluate(p)
    assert receipt.decision is Decision.REFUSE
    assert "approval_too_old:flight" in receipt.reasons
