#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cryo_telemetry_half_life import CryoTelemetryHalfLife, CryoTelemetryHalfLifeRequest, Decision


def _payload() -> dict:
    return {
        "now": 1000.0,
        "command": {"name": "simulation-stage-transition", "mode": "simulation"},
        "required_channels": ["tank.pressure", "tank.temperature"],
        "min_freshness": 0.5,
        "telemetry": [
            {"channel": "tank.pressure", "observed_at": 996.0, "half_life_s": 20.0, "quality": 1.0, "value": 42.0},
            {"channel": "tank.temperature", "observed_at": 997.0, "half_life_s": 20.0, "quality": 0.95, "value": 90.0},
        ],
        "required_roles": ["operator", "safety"],
        "approval_ttl_s": 30.0,
        "approvals": [
            {"key_id": "operator-key", "principal": "operator-a", "role": "operator", "approved_at": 998.0},
            {"key_id": "safety-key", "principal": "safety-b", "role": "safety", "approved_at": 999.0},
        ],
    }


def main() -> int:
    engine = CryoTelemetryHalfLife()
    baseline_payload = _payload()
    allowed = engine.evaluate(CryoTelemetryHalfLifeRequest("sim-transition", baseline_payload, budget=4.0))
    if allowed.decision is not Decision.ALLOW:
        print(json.dumps(allowed.as_dict(), indent=2, sort_keys=True))
        return 2

    verified_payload = _payload()
    verified_payload["evidence_digest"] = allowed.result["evidence_digest"]
    evidence_verified = engine.evaluate(
        CryoTelemetryHalfLifeRequest("sim-transition", verified_payload, budget=4.0)
    )

    stale_payload = _payload()
    stale_payload["telemetry"][0]["observed_at"] = 900.0
    stale = engine.evaluate(CryoTelemetryHalfLifeRequest("sim-transition", stale_payload, budget=4.0))

    bypass_payload = _payload()
    bypass_payload["approvals"][1]["principal"] = "operator-a"
    bypass_payload["approvals"].append(
        {"key_id": "observer-key", "principal": "observer-b", "role": "observer", "approved_at": 999.0}
    )
    independence_bypass = engine.evaluate(
        CryoTelemetryHalfLifeRequest("sim-transition", bypass_payload, budget=4.0)
    )

    tampered = deepcopy(verified_payload)
    tampered["telemetry"][0]["value"] = 43.0
    evidence_mismatch = engine.evaluate(
        CryoTelemetryHalfLifeRequest("sim-transition", tampered, budget=4.0)
    )

    print(
        json.dumps(
            {
                "eligible": allowed.as_dict(),
                "evidence_verified": evidence_verified.as_dict(),
                "stale_telemetry": stale.as_dict(),
                "required_role_independence_bypass": independence_bypass.as_dict(),
                "evidence_mismatch": evidence_mismatch.as_dict(),
            },
            indent=2,
            sort_keys=True,
        )
    )

    if evidence_verified.decision is not Decision.ALLOW:
        return 3
    if stale.decision is not Decision.REFUSE or "telemetry_tank.pressure_stale" not in stale.reasons:
        return 4
    if independence_bypass.decision is not Decision.REFUSE or "required_role_approvals_not_independent" not in independence_bypass.reasons:
        return 5
    if evidence_mismatch.decision is not Decision.REFUSE or "evidence_digest_mismatch" not in evidence_mismatch.reasons:
        return 6
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
