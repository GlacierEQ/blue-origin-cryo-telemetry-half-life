#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
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
        "evidence_digest": "d" * 64,
    }


def main() -> int:
    engine = CryoTelemetryHalfLife()
    allowed = engine.evaluate(CryoTelemetryHalfLifeRequest("sim-transition", _payload(), budget=4.0))

    stale_payload = _payload()
    stale_payload["telemetry"][0]["observed_at"] = 900.0
    stale = engine.evaluate(CryoTelemetryHalfLifeRequest("sim-transition", stale_payload, budget=4.0))

    reused_key_payload = _payload()
    reused_key_payload["approvals"][1]["principal"] = "operator-a"
    reused_key = engine.evaluate(CryoTelemetryHalfLifeRequest("sim-transition", reused_key_payload, budget=4.0))

    print(json.dumps({
        "eligible": allowed.as_dict(),
        "stale_telemetry": stale.as_dict(),
        "reused_principal": reused_key.as_dict(),
    }, indent=2, sort_keys=True))

    if allowed.decision is not Decision.ALLOW:
        return 2
    if stale.decision is not Decision.REFUSE or "telemetry_tank.pressure_stale" not in stale.reasons:
        return 3
    if reused_key.decision is not Decision.REFUSE or "dual_key_requires_distinct_principals" not in reused_key.reasons:
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
