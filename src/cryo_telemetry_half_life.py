"""Deterministic telemetry-freshness and dual-key authorization kernel.

This module does not actuate hardware. It evaluates whether a declared command
has sufficiently fresh telemetry and independent approvals to be eligible for a
separate executor or simulator.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


def _canonical_json(value: Any, *, path: str = "value") -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path}_non_finite")
        return value
    if isinstance(value, list):
        return [_canonical_json(item, path=f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path}_key_not_string")
            out[key] = _canonical_json(item, path=f"{path}.{key}")
        return out
    raise ValueError(f"{path}_not_canonical_json")


def _digest(obj: object) -> str:
    payload = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


@dataclass(frozen=True)
class CryoTelemetryHalfLifeRequest:
    subject_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    budget: float = 4.0
    grant_id: str | None = None
    not_after: float | None = None


@dataclass(frozen=True)
class CryoTelemetryHalfLifeReceipt:
    decision: Decision
    reasons: tuple[str, ...]
    digest: str
    metrics: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reasons": list(self.reasons),
            "digest": self.digest,
            "metrics": self.metrics,
            "result": self.result,
        }


class CryoTelemetryHalfLife:
    """Evaluate telemetry freshness and independent approval requirements."""

    VALID_PAYLOAD_KEYS = frozenset(
        {
            "now",
            "command",
            "telemetry",
            "required_channels",
            "min_freshness",
            "approvals",
            "required_roles",
            "approval_ttl_s",
            "evidence_digest",
        }
    )
    BASE_WORK_UNITS = 1.0
    TELEMETRY_WORK_UNITS = 0.05
    APPROVAL_WORK_UNITS = 0.05
    DEFAULT_MIN_FRESHNESS = 0.5
    DEFAULT_REQUIRED_ROLES = ("operator", "safety")

    @staticmethod
    def _positive_number(value: Any, name: str, *, allow_zero: bool = False) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{name}_invalid")
        number = float(value)
        if not math.isfinite(number) or (number < 0 if allow_zero else number <= 0):
            raise ValueError(f"{name}_invalid")
        return number

    @staticmethod
    def _normalize_roles(raw: Any) -> tuple[str, ...]:
        if raw is None:
            return CryoTelemetryHalfLife.DEFAULT_REQUIRED_ROLES
        if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
            raise ValueError("required_roles_invalid")
        roles = tuple(sorted({str(role).strip().lower() for role in raw if str(role).strip()}))
        if len(roles) < 2:
            raise ValueError("dual_key_requires_two_roles")
        return roles

    @classmethod
    def _normalize_telemetry(cls, raw: Any, index: int, now: float) -> tuple[dict[str, Any] | None, str | None]:
        if not isinstance(raw, Mapping):
            return None, f"telemetry_{index}_not_object"
        channel = str(raw.get("channel", "")).strip()
        if not channel:
            return None, f"telemetry_{index}_channel_missing"
        try:
            observed_at = cls._positive_number(raw.get("observed_at"), f"telemetry_{channel}_observed_at", allow_zero=True)
            half_life_s = cls._positive_number(raw.get("half_life_s"), f"telemetry_{channel}_half_life")
        except ValueError as exc:
            return None, str(exc)
        if observed_at > now:
            return None, f"telemetry_{channel}_from_future"
        try:
            quality = float(raw.get("quality", 1.0))
            if not math.isfinite(quality) or not 0.0 <= quality <= 1.0:
                raise ValueError
        except (TypeError, ValueError):
            return None, f"telemetry_{channel}_quality_invalid"
        age_s = now - observed_at
        freshness = quality * math.pow(0.5, age_s / half_life_s)
        normalized = {
            "channel": channel,
            "observed_at": observed_at,
            "half_life_s": half_life_s,
            "quality": quality,
            "age_s": age_s,
            "freshness": freshness,
        }
        if "value" in raw:
            try:
                normalized["value"] = _canonical_json(raw["value"], path=f"telemetry.{channel}.value")
            except ValueError as exc:
                return None, str(exc)
        if raw.get("source_digest") is not None:
            source_digest = str(raw["source_digest"]).lower()
            if not _SHA256.fullmatch(source_digest):
                return None, f"telemetry_{channel}_source_digest_invalid"
            normalized["source_digest"] = source_digest
        return normalized, None

    @classmethod
    def _normalize_approval(cls, raw: Any, index: int, now: float, ttl_s: float) -> tuple[dict[str, Any] | None, str | None]:
        if not isinstance(raw, Mapping):
            return None, f"approval_{index}_not_object"
        key_id = str(raw.get("key_id", "")).strip()
        principal = str(raw.get("principal", "")).strip()
        role = str(raw.get("role", "")).strip().lower()
        if not key_id:
            return None, f"approval_{index}_key_id_missing"
        if not principal:
            return None, f"approval_{index}_principal_missing"
        if not role:
            return None, f"approval_{index}_role_missing"
        try:
            approved_at = cls._positive_number(raw.get("approved_at"), f"approval_{key_id}_approved_at", allow_zero=True)
        except ValueError as exc:
            return None, str(exc)
        if approved_at > now:
            return None, f"approval_{key_id}_from_future"
        age_s = now - approved_at
        if age_s > ttl_s:
            return None, f"approval_{key_id}_expired"
        return {
            "key_id": key_id,
            "principal": principal,
            "role": role,
            "approved_at": approved_at,
            "age_s": age_s,
        }, None

    def evaluate(self, req: CryoTelemetryHalfLifeRequest) -> CryoTelemetryHalfLifeReceipt:
        if not isinstance(req, CryoTelemetryHalfLifeRequest):
            raise TypeError("req must be CryoTelemetryHalfLifeRequest")

        reasons: list[str] = []
        subject_id = str(req.subject_id or "").strip()
        if not subject_id:
            reasons.append("subject_id_missing")
        try:
            budget = self._positive_number(req.budget, "budget")
        except ValueError:
            budget = 0.0
            reasons.append("budget_non_positive")
        if not isinstance(req.payload, Mapping):
            return self._receipt(req, Decision.REFUSE, reasons + ["payload_invalid"])

        unknown = set(req.payload) - self.VALID_PAYLOAD_KEYS
        if unknown:
            reasons.append("payload_keys_unknown:" + ",".join(sorted(unknown)))

        try:
            now = self._positive_number(req.payload.get("now"), "now", allow_zero=True)
        except ValueError as exc:
            reasons.append(str(exc))
            now = 0.0

        command_raw = req.payload.get("command")
        if not isinstance(command_raw, Mapping):
            reasons.append("command_missing")
            command: dict[str, Any] = {}
        else:
            try:
                command = _canonical_json(command_raw, path="command")
            except ValueError as exc:
                reasons.append(str(exc))
                command = {}
        command_name = str(command.get("name", "")).strip()
        if not command_name:
            reasons.append("command_name_missing")

        try:
            min_freshness = float(req.payload.get("min_freshness", self.DEFAULT_MIN_FRESHNESS))
            if not math.isfinite(min_freshness) or not 0.0 < min_freshness <= 1.0:
                raise ValueError
        except (TypeError, ValueError):
            min_freshness = self.DEFAULT_MIN_FRESHNESS
            reasons.append("min_freshness_invalid")

        required_channels_raw = req.payload.get("required_channels", [])
        if not isinstance(required_channels_raw, Sequence) or isinstance(required_channels_raw, (str, bytes, bytearray)):
            reasons.append("required_channels_invalid")
            required_channels: tuple[str, ...] = ()
        else:
            required_channels = tuple(sorted({str(channel).strip() for channel in required_channels_raw if str(channel).strip()}))
        if not required_channels:
            reasons.append("required_channels_empty")

        telemetry_raw = req.payload.get("telemetry")
        if not isinstance(telemetry_raw, list):
            reasons.append("telemetry_missing")
            telemetry_raw = []
        telemetry: list[dict[str, Any]] = []
        seen_channels: set[str] = set()
        for index, raw in enumerate(telemetry_raw):
            sample, error = self._normalize_telemetry(raw, index, now)
            if error:
                reasons.append(error)
                continue
            assert sample is not None
            if sample["channel"] in seen_channels:
                reasons.append(f"telemetry_{sample['channel']}_duplicate")
                continue
            seen_channels.add(sample["channel"])
            telemetry.append(sample)
        telemetry.sort(key=lambda item: item["channel"])
        by_channel = {sample["channel"]: sample for sample in telemetry}
        for channel in required_channels:
            sample = by_channel.get(channel)
            if sample is None:
                reasons.append(f"telemetry_{channel}_missing")
            elif sample["freshness"] < min_freshness:
                reasons.append(f"telemetry_{channel}_stale")

        try:
            required_roles = self._normalize_roles(req.payload.get("required_roles"))
        except ValueError as exc:
            reasons.append(str(exc))
            required_roles = self.DEFAULT_REQUIRED_ROLES
        try:
            approval_ttl_s = self._positive_number(req.payload.get("approval_ttl_s"), "approval_ttl_s")
        except ValueError as exc:
            reasons.append(str(exc))
            approval_ttl_s = 0.0

        approvals_raw = req.payload.get("approvals")
        if not isinstance(approvals_raw, list):
            reasons.append("approvals_missing")
            approvals_raw = []
        approvals: list[dict[str, Any]] = []
        key_ids: set[str] = set()
        principals: set[str] = set()
        for index, raw in enumerate(approvals_raw):
            approval, error = self._normalize_approval(raw, index, now, approval_ttl_s or 1.0)
            if error:
                reasons.append(error)
                continue
            assert approval is not None
            if approval["key_id"] in key_ids:
                reasons.append(f"approval_{approval['key_id']}_duplicate_key")
                continue
            key_ids.add(approval["key_id"])
            approvals.append(approval)
            principals.add(approval["principal"])
        approvals.sort(key=lambda item: (item["role"], item["principal"], item["key_id"]))

        approved_roles = {approval["role"] for approval in approvals}
        for role in required_roles:
            if role not in approved_roles:
                reasons.append(f"approval_role_{role}_missing")
        if len(principals) < 2:
            reasons.append("dual_key_requires_distinct_principals")
        if len(key_ids) < 2:
            reasons.append("dual_key_requires_distinct_keys")

        evidence_digest = req.payload.get("evidence_digest")
        if evidence_digest is not None:
            evidence_digest = str(evidence_digest).lower()
            if not _SHA256.fullmatch(evidence_digest):
                reasons.append("evidence_digest_invalid")

        work_units = (
            self.BASE_WORK_UNITS
            + len(telemetry) * self.TELEMETRY_WORK_UNITS
            + len(approvals) * self.APPROVAL_WORK_UNITS
        )
        if work_units > budget:
            reasons.append("work_budget_exceeded")

        required_samples = [by_channel[channel] for channel in required_channels if channel in by_channel]
        min_observed_freshness = min((sample["freshness"] for sample in required_samples), default=0.0)
        result = {
            "schema": "glaciereq.telemetry-half-life.v1",
            "subject_id": subject_id,
            "now": now,
            "command": command,
            "required_channels": list(required_channels),
            "min_freshness": min_freshness,
            "telemetry": telemetry,
            "required_roles": list(required_roles),
            "approval_ttl_s": approval_ttl_s,
            "approvals": approvals,
            "evidence_digest": evidence_digest,
            "eligible": not reasons,
        }
        decision = Decision.REFUSE if reasons else Decision.ALLOW
        if not reasons:
            reasons = ["fresh_telemetry_and_dual_key_verified"]
        metrics = {
            "required_channel_count": len(required_channels),
            "telemetry_count": len(telemetry),
            "approval_count": len(approvals),
            "distinct_principals": len(principals),
            "distinct_keys": len(key_ids),
            "min_observed_freshness": min_observed_freshness,
            "work_units": work_units,
            "budget_units": budget,
        }
        digest = _digest({"decision": decision.value, "reasons": reasons, "result": result, "metrics": metrics})
        return CryoTelemetryHalfLifeReceipt(decision, tuple(reasons), digest, metrics, result)

    @staticmethod
    def _receipt(req: CryoTelemetryHalfLifeRequest, decision: Decision, reasons: Sequence[str]) -> CryoTelemetryHalfLifeReceipt:
        unique = tuple(dict.fromkeys(reasons))
        result = {"subject_id": str(req.subject_id or ""), "eligible": False}
        metrics = {"required_channel_count": 0, "telemetry_count": 0, "approval_count": 0}
        digest = _digest({"decision": decision.value, "reasons": list(unique), "result": result, "metrics": metrics})
        return CryoTelemetryHalfLifeReceipt(decision, unique, digest, metrics, result)


Mechanism = CryoTelemetryHalfLife


def cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate telemetry freshness and independent command approvals from JSON.")
    parser.add_argument("--input", "-i", help="request JSON file; defaults to stdin")
    args = parser.parse_args(argv)
    try:
        raw = Path(args.input).read_text(encoding="utf-8") if args.input else sys.stdin.read()
        data = json.loads(raw)
        if not isinstance(data, Mapping):
            raise ValueError("request JSON must be an object")
        request = CryoTelemetryHalfLifeRequest(
            subject_id=str(data.get("subject_id", "")),
            payload=dict(data.get("payload") or {}),
            budget=data.get("budget", 4.0),
            grant_id=data.get("grant_id"),
            not_after=data.get("not_after"),
        )
        receipt = CryoTelemetryHalfLife().evaluate(request)
    except Exception as exc:
        print(json.dumps({"decision": "REFUSE", "reasons": [f"cli_input_error:{type(exc).__name__}:{exc}"]}, sort_keys=True))
        return 2
    print(json.dumps(receipt.as_dict(), indent=2, sort_keys=True))
    return 0 if receipt.decision is Decision.ALLOW else 2
