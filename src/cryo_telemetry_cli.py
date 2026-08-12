from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryo_telemetry_half_life import CryoTelemetryHalfLife, CryoTelemetryHalfLifeRequest, Decision


def demo_payload() -> dict:
    telemetry = [
        {"channel": "tank_pressure", "value": 42.0, "unit": "psi", "observed_at": 90.0, "half_life_s": 30.0, "healthy": True},
        {"channel": "line_temp", "value": -180.0, "unit": "C", "observed_at": 95.0, "half_life_s": 20.0, "healthy": True},
    ]
    probe = CryoTelemetryHalfLife().evaluate(CryoTelemetryHalfLifeRequest("demo", {"now": 100.0, "scope": "valve.actuate", "required_channels": ["tank_pressure", "line_temp"], "telemetry": telemetry, "approvals": [], "min_authority_keys": 2, "max_approval_age_s": 30.0}, 1.0))
    digest = probe.metrics["result"]["telemetry_digest"]
    return {"now": 100.0, "scope": "valve.actuate", "required_channels": ["tank_pressure", "line_temp"], "telemetry": telemetry, "approvals": [
        {"authority_id": "flight", "authority_group": "flight-safety", "approved_at": 98.0, "expires_at": 120.0, "scopes": ["valve.actuate"], "telemetry_digest": digest},
        {"authority_id": "test", "authority_group": "test-ops", "approved_at": 99.0, "expires_at": 120.0, "scopes": ["valve.actuate"], "telemetry_digest": digest},
    ], "min_authority_keys": 2, "max_approval_age_s": 30.0}


def main() -> int:
    parser = argparse.ArgumentParser(description="Authorize cryogenic actuation from fresh telemetry and dual-key evidence")
    parser.add_argument("--input", type=Path)
    parser.add_argument("--subject", default="cryo-demo")
    args = parser.parse_args()
    payload = json.loads(args.input.read_text()) if args.input else demo_payload()
    receipt = CryoTelemetryHalfLife().evaluate(CryoTelemetryHalfLifeRequest(args.subject, payload, 1.0))
    print(json.dumps(receipt.as_dict(), indent=2, sort_keys=True))
    return 0 if receipt.decision is Decision.ALLOW else 2


if __name__ == "__main__":
    raise SystemExit(main())
