"""Cryo Telemetry Half-Life.

Refuses actuation when required telemetry has decayed past its declared half-life
or when command authority is not backed by fresh, independent dual-key approval
bound to the exact telemetry snapshot.
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


@dataclass(frozen=True)
class CryoTelemetryHalfLifeRequest:
    subject_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    budget: float = 1.0
    grant_id: str | None = None
    not_after: float | None = None


@dataclass(frozen=True)
class CryoTelemetryHalfLifeReceipt:
    decision: Decision
    reasons: tuple[str, ...]
    digest: str
    metrics: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"decision": self.decision.value, "reasons": list(self.reasons), "digest": self.digest, "metrics": self.metrics}


class TelemetryFenceError(ValueError):
    pass


class CryoTelemetryHalfLife:
    MIN_BUDGET = 0.0

    @staticmethod
    def _num(value: Any, label: str, *, minimum: float | None = None) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TelemetryFenceError(f"{label}_invalid")
        value = float(value)
        if not math.isfinite(value):
            raise TelemetryFenceError(f"{label}_not_finite")
        if minimum is not None and value < minimum:
            raise TelemetryFenceError(f"{label}_below_minimum")
        return value

    @staticmethod
    def _id(value: Any, label: str) -> str:
        value = str(value or "").strip()
        if not value:
            raise TelemetryFenceError(f"{label}_missing")
        return value

    @classmethod
    def _telemetry(cls, raw: Any, now: float) -> tuple[dict[str, Any], list[str]]:
        if not isinstance(raw, list) or not raw:
            raise TelemetryFenceError("telemetry_missing")
        rows: dict[str, Any] = {}
        stale: list[str] = []
        for index, item in enumerate(raw):
            if not isinstance(item, dict):
                raise TelemetryFenceError(f"telemetry_{index}_not_object")
            channel = cls._id(item.get("channel"), f"telemetry_{index}_channel")
            if channel in rows:
                raise TelemetryFenceError(f"duplicate_telemetry_channel:{channel}")
            observed_at = cls._num(item.get("observed_at"), f"telemetry_{index}_observed_at", minimum=0)
            half_life_s = cls._num(item.get("half_life_s"), f"telemetry_{index}_half_life_s", minimum=0.001)
            if observed_at > now:
                raise TelemetryFenceError(f"telemetry_from_future:{channel}")
            age = now - observed_at
            freshness = 2 ** (-age / half_life_s)
            row = {
                "channel": channel,
                "value": item.get("value"),
                "unit": cls._id(item.get("unit"), f"telemetry_{index}_unit"),
                "observed_at": observed_at,
                "half_life_s": half_life_s,
                "age_s": round(age, 9),
                "freshness": round(freshness, 12),
                "healthy": item.get("healthy") is True,
            }
            rows[channel] = row
            if age > half_life_s:
                stale.append(channel)
            if not row["healthy"]:
                stale.append(f"{channel}:unhealthy")
        return rows, sorted(set(stale))

    @classmethod
    def _approvals(cls, raw: Any, *, now: float, scope: str, telemetry_digest: str, min_keys: int, max_age_s: float) -> tuple[list[dict[str, Any]], list[str]]:
        if not isinstance(raw, list):
            raise TelemetryFenceError("approvals_not_list")
        accepted: list[dict[str, Any]] = []
        reasons: list[str] = []
        seen_authorities: set[str] = set()
        seen_groups: set[str] = set()
        for index, item in enumerate(raw):
            if not isinstance(item, dict):
                raise TelemetryFenceError(f"approval_{index}_not_object")
            authority_id = cls._id(item.get("authority_id"), f"approval_{index}_authority_id")
            group = cls._id(item.get("authority_group"), f"approval_{index}_authority_group")
            approved_at = cls._num(item.get("approved_at"), f"approval_{index}_approved_at", minimum=0)
            expires_at = cls._num(item.get("expires_at"), f"approval_{index}_expires_at", minimum=0)
            scopes = item.get("scopes")
            if not isinstance(scopes, list) or scope not in {str(v) for v in scopes}:
                reasons.append(f"approval_scope_denied:{authority_id}")
                continue
            if authority_id in seen_authorities:
                reasons.append(f"duplicate_authority:{authority_id}")
                continue
            if approved_at > now or now > expires_at:
                reasons.append(f"approval_not_current:{authority_id}")
                continue
            if now - approved_at > max_age_s:
                reasons.append(f"approval_too_old:{authority_id}")
                continue
            if str(item.get("telemetry_digest", "")) != telemetry_digest:
                reasons.append(f"approval_telemetry_mismatch:{authority_id}")
                continue
            seen_authorities.add(authority_id)
            seen_groups.add(group)
            accepted.append({"authority_id": authority_id, "authority_group": group, "approved_at": approved_at, "expires_at": expires_at})
        if len(accepted) < min_keys:
            reasons.append("dual_key_approval_missing")
        if len(seen_groups) < min_keys:
            reasons.append("independent_authority_groups_missing")
        return accepted, reasons

    def evaluate(self, req: CryoTelemetryHalfLifeRequest) -> CryoTelemetryHalfLifeReceipt:
        reasons: list[str] = []
        if not str(req.subject_id or "").strip():
            reasons.append("subject_id_missing")
        if isinstance(req.budget, bool) or not isinstance(req.budget, (int, float)) or not math.isfinite(float(req.budget)) or float(req.budget) <= self.MIN_BUDGET:
            reasons.append("budget_non_positive_or_invalid")
        payload = req.payload if isinstance(req.payload, dict) else {}
        if not isinstance(req.payload, dict):
            reasons.append("payload_not_object")
        result = None
        try:
            now = self._num(payload.get("now"), "now", minimum=0)
            scope = self._id(payload.get("scope"), "scope")
            required_channels = payload.get("required_channels")
            if not isinstance(required_channels, list) or not required_channels:
                raise TelemetryFenceError("required_channels_missing")
            required = {str(v).strip() for v in required_channels if str(v).strip()}
            telemetry, stale = self._telemetry(payload.get("telemetry"), now)
            missing = sorted(required - set(telemetry))
            stale_required = sorted(item for item in stale if item.split(":", 1)[0] in required)
            snapshot = {key: telemetry[key] for key in sorted(required & set(telemetry))}
            telemetry_digest = _digest(snapshot)
            min_keys = int(self._num(payload.get("min_authority_keys", 2), "min_authority_keys", minimum=2))
            max_approval_age_s = self._num(payload.get("max_approval_age_s", 30.0), "max_approval_age_s", minimum=0.001)
            approvals, approval_reasons = self._approvals(payload.get("approvals"), now=now, scope=scope, telemetry_digest=telemetry_digest, min_keys=min_keys, max_age_s=max_approval_age_s)
            if missing:
                reasons.append("required_telemetry_missing")
            if stale_required:
                reasons.append("required_telemetry_past_half_life_or_unhealthy")
            reasons.extend(approval_reasons)
            result = {
                "actuation_scope": scope,
                "authorized": not reasons,
                "telemetry_digest": telemetry_digest,
                "required_channels": sorted(required),
                "missing_channels": missing,
                "stale_or_unhealthy": stale_required,
                "freshness": {key: telemetry[key]["freshness"] for key in sorted(required & set(telemetry))},
                "accepted_authorities": approvals,
            }
        except TelemetryFenceError as exc:
            reasons.append(str(exc))
        decision = Decision.REFUSE if reasons else Decision.ALLOW
        metrics = {"result": result}
        body = {"subject_id": req.subject_id, "decision": decision.value, "reasons": reasons, "metrics": metrics}
        return CryoTelemetryHalfLifeReceipt(decision, tuple(reasons or ["fresh_dual_key_actuation_authorized"]), _digest(body), metrics)


Mechanism = CryoTelemetryHalfLife
