"""Deterministic telemetry-freshness and independent-approval eligibility kernel.

This module never actuates hardware. It evaluates whether a declared simulated
command has sufficiently fresh telemetry and an independent set of approvals
before a separate executor or simulator may consider the request.
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


class _JsonCounter:
    def __init__(self, *, max_nodes: int, max_depth: int, max_string_chars: int) -> None:
        self.max_nodes = max_nodes
        self.max_depth = max_depth
        self.max_string_chars = max_string_chars
        self.nodes = 0

    def touch(self, path: str, depth: int) -> None:
        self.nodes += 1
        if self.nodes > self.max_nodes:
            raise ValueError(f"{path}_node_limit_exceeded")
        if depth > self.max_depth:
            raise ValueError(f"{path}_depth_limit_exceeded")


def _canonical_json(
    value: Any,
    *,
    path: str = "value",
    counter: _JsonCounter | None = None,
    depth: int = 0,
) -> Any:
    counter = counter or _JsonCounter(max_nodes=2048, max_depth=16, max_string_chars=65_536)
    counter.touch(path, depth)
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        if len(value) > counter.max_string_chars:
            raise ValueError(f"{path}_string_too_large")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path}_non_finite")
        return value
    if isinstance(value, list):
        return [
            _canonical_json(item, path=f"{path}[{index}]", counter=counter, depth=depth + 1)
            for index, item in enumerate(value)
        ]
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path}_key_not_string")
            if len(key) > counter.max_string_chars:
                raise ValueError(f"{path}_key_too_large")
            out[key] = _canonical_json(
                item,
                path=f"{path}.{key}",
                counter=counter,
                depth=depth + 1,
            )
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
    MAX_TELEMETRY = 128
    MAX_APPROVALS = 64
    MAX_REQUIRED_CHANNELS = 64
    MAX_REQUIRED_ROLES = 8
    MAX_JSON_NODES = 2048
    MAX_JSON_DEPTH = 16
    MAX_STRING_CHARS = 65_536
    MAX_CLI_INPUT_CHARS = 2_000_000

    @staticmethod
    def _positive_number(value: Any, name: str, *, allow_zero: bool = False) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{name}_invalid")
        number = float(value)
        if not math.isfinite(number) or (number < 0 if allow_zero else number <= 0):
            raise ValueError(f"{name}_invalid")
        return number

    @staticmethod
    def _strict_text(value: Any, name: str, *, lower: bool = False) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{name}_type_invalid")
        normalized = value.strip()
        if not normalized:
            raise ValueError(f"{name}_missing")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in normalized):
            raise ValueError(f"{name}_control_character")
        return normalized.lower() if lower else normalized

    @classmethod
    def _normalize_roles(cls, raw: Any) -> tuple[str, ...]:
        if raw is None:
            return cls.DEFAULT_REQUIRED_ROLES
        if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
            raise ValueError("required_roles_invalid")
        if len(raw) > cls.MAX_REQUIRED_ROLES:
            raise ValueError("required_roles_over_limit")
        values: set[str] = set()
        for index, role in enumerate(raw):
            values.add(cls._strict_text(role, f"required_role_{index}", lower=True))
        roles = tuple(sorted(values))
        if len(roles) < 2:
            raise ValueError("dual_key_requires_two_roles")
        return roles

    @classmethod
    def _normalize_channels(cls, raw: Any) -> tuple[str, ...]:
        if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
            raise ValueError("required_channels_invalid")
        if len(raw) > cls.MAX_REQUIRED_CHANNELS:
            raise ValueError("required_channels_over_limit")
        values: set[str] = set()
        for index, channel in enumerate(raw):
            values.add(cls._strict_text(channel, f"required_channel_{index}"))
        channels = tuple(sorted(values))
        if not channels:
            raise ValueError("required_channels_empty")
        return channels

    @classmethod
    def _bounded_json(cls, value: Any, path: str) -> Any:
        return _canonical_json(
            value,
            path=path,
            counter=_JsonCounter(
                max_nodes=cls.MAX_JSON_NODES,
                max_depth=cls.MAX_JSON_DEPTH,
                max_string_chars=cls.MAX_STRING_CHARS,
            ),
        )

    @classmethod
    def _normalize_telemetry(
        cls, raw: Any, index: int, now: float
    ) -> tuple[dict[str, Any] | None, str | None]:
        if not isinstance(raw, Mapping):
            return None, f"telemetry_{index}_not_object"
        try:
            channel = cls._strict_text(raw.get("channel"), f"telemetry_{index}_channel")
        except ValueError as exc:
            return None, str(exc)
        try:
            observed_at = cls._positive_number(
                raw.get("observed_at"), f"telemetry_{channel}_observed_at", allow_zero=True
            )
            half_life_s = cls._positive_number(
                raw.get("half_life_s"), f"telemetry_{channel}_half_life"
            )
        except ValueError as exc:
            return None, str(exc)
        if observed_at > now:
            return None, f"telemetry_{channel}_from_future"
        quality_raw = raw.get("quality", 1.0)
        if isinstance(quality_raw, bool) or not isinstance(quality_raw, (int, float)):
            return None, f"telemetry_{channel}_quality_invalid"
        quality = float(quality_raw)
        if not math.isfinite(quality) or not 0.0 <= quality <= 1.0:
            return None, f"telemetry_{channel}_quality_invalid"
        age_s = now - observed_at
        freshness = quality * math.pow(0.5, age_s / half_life_s)
        normalized: dict[str, Any] = {
            "channel": channel,
            "observed_at": observed_at,
            "half_life_s": half_life_s,
            "quality": quality,
            "age_s": age_s,
            "freshness": freshness,
        }
        if "value" in raw:
            try:
                normalized["value"] = cls._bounded_json(
                    raw["value"], f"telemetry.{channel}.value"
                )
            except ValueError as exc:
                return None, str(exc)
        if raw.get("source_digest") is not None:
            source_raw = raw["source_digest"]
            if not isinstance(source_raw, str):
                return None, f"telemetry_{channel}_source_digest_type_invalid"
            source_digest = source_raw.lower()
            if not _SHA256.fullmatch(source_digest):
                return None, f"telemetry_{channel}_source_digest_invalid"
            normalized["source_digest"] = source_digest
        return normalized, None

    @classmethod
    def _normalize_approval(
        cls, raw: Any, index: int, now: float, ttl_s: float
    ) -> tuple[dict[str, Any] | None, str | None]:
        if not isinstance(raw, Mapping):
            return None, f"approval_{index}_not_object"
        try:
            key_id = cls._strict_text(raw.get("key_id"), f"approval_{index}_key_id")
            principal = cls._strict_text(
                raw.get("principal"), f"approval_{index}_principal"
            )
            role = cls._strict_text(raw.get("role"), f"approval_{index}_role", lower=True)
        except ValueError as exc:
            return None, str(exc)
        try:
            approved_at = cls._positive_number(
                raw.get("approved_at"), f"approval_{key_id}_approved_at", allow_zero=True
            )
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

    @staticmethod
    def _select_independent_approvals(
        approvals: Sequence[Mapping[str, Any]], required_roles: Sequence[str]
    ) -> tuple[dict[str, Any], ...] | None:
        by_role: dict[str, list[dict[str, Any]]] = {role: [] for role in required_roles}
        for approval in approvals:
            role = str(approval["role"])
            if role in by_role:
                by_role[role].append(dict(approval))
        for role in required_roles:
            by_role[role].sort(
                key=lambda item: (item["principal"], item["key_id"], item["approved_at"])
            )
            if not by_role[role]:
                return None

        roles = tuple(required_roles)

        def search(
            index: int,
            used_principals: frozenset[str],
            used_keys: frozenset[str],
        ) -> tuple[dict[str, Any], ...] | None:
            if index == len(roles):
                return ()
            role = roles[index]
            for approval in by_role[role]:
                principal = str(approval["principal"])
                key_id = str(approval["key_id"])
                if principal in used_principals or key_id in used_keys:
                    continue
                rest = search(
                    index + 1,
                    used_principals | {principal},
                    used_keys | {key_id},
                )
                if rest is not None:
                    return (approval,) + rest
            return None

        return search(0, frozenset(), frozenset())

    def evaluate(self, req: CryoTelemetryHalfLifeRequest) -> CryoTelemetryHalfLifeReceipt:
        if not isinstance(req, CryoTelemetryHalfLifeRequest):
            raise TypeError("req must be CryoTelemetryHalfLifeRequest")

        reasons: list[str] = []
        if not isinstance(req.subject_id, str) or not req.subject_id.strip():
            subject_id = ""
            reasons.append("subject_id_invalid")
        else:
            subject_id = req.subject_id.strip()
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

        grant_id: str | None = None
        if req.grant_id is not None:
            try:
                grant_id = self._strict_text(req.grant_id, "grant_id")
            except ValueError as exc:
                reasons.append(str(exc))

        not_after: float | None = None
        if req.not_after is not None:
            try:
                not_after = self._positive_number(req.not_after, "not_after", allow_zero=True)
                if now > not_after:
                    reasons.append("request_expired")
            except ValueError as exc:
                reasons.append(str(exc))

        command_raw = req.payload.get("command")
        if not isinstance(command_raw, Mapping):
            reasons.append("command_missing")
            command: dict[str, Any] = {}
        else:
            try:
                command = self._bounded_json(command_raw, "command")
            except ValueError as exc:
                reasons.append(str(exc))
                command = {}
        command_name_raw = command.get("name")
        if not isinstance(command_name_raw, str) or not command_name_raw.strip():
            reasons.append("command_name_invalid")

        min_freshness_raw = req.payload.get(
            "min_freshness", self.DEFAULT_MIN_FRESHNESS
        )
        if isinstance(min_freshness_raw, bool) or not isinstance(
            min_freshness_raw, (int, float)
        ):
            min_freshness = self.DEFAULT_MIN_FRESHNESS
            reasons.append("min_freshness_invalid")
        else:
            min_freshness = float(min_freshness_raw)
            if not math.isfinite(min_freshness) or not 0.0 < min_freshness <= 1.0:
                min_freshness = self.DEFAULT_MIN_FRESHNESS
                reasons.append("min_freshness_invalid")

        try:
            required_channels = self._normalize_channels(
                req.payload.get("required_channels", [])
            )
        except ValueError as exc:
            reasons.append(str(exc))
            required_channels = ()

        try:
            required_roles = self._normalize_roles(req.payload.get("required_roles"))
        except ValueError as exc:
            reasons.append(str(exc))
            required_roles = self.DEFAULT_REQUIRED_ROLES

        try:
            approval_ttl_s = self._positive_number(
                req.payload.get("approval_ttl_s"), "approval_ttl_s"
            )
        except ValueError as exc:
            reasons.append(str(exc))
            approval_ttl_s = 0.0

        telemetry_raw = req.payload.get("telemetry")
        if not isinstance(telemetry_raw, list):
            reasons.append("telemetry_missing")
            telemetry_raw = []
        elif len(telemetry_raw) > self.MAX_TELEMETRY:
            reasons.append("telemetry_over_limit")
            telemetry_raw = []

        approvals_raw = req.payload.get("approvals")
        if not isinstance(approvals_raw, list):
            reasons.append("approvals_missing")
            approvals_raw = []
        elif len(approvals_raw) > self.MAX_APPROVALS:
            reasons.append("approvals_over_limit")
            approvals_raw = []

        preflight_work_units = (
            self.BASE_WORK_UNITS
            + len(telemetry_raw) * self.TELEMETRY_WORK_UNITS
            + len(approvals_raw) * self.APPROVAL_WORK_UNITS
        )
        if preflight_work_units > budget:
            reasons.append("work_budget_exceeded")
            return self._receipt(
                req,
                Decision.REFUSE,
                reasons,
                metrics={"work_units": preflight_work_units, "budget_units": budget},
            )

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

        approvals: list[dict[str, Any]] = []
        key_ids: set[str] = set()
        for index, raw in enumerate(approvals_raw):
            approval, error = self._normalize_approval(
                raw, index, now, approval_ttl_s or 1.0
            )
            if error:
                reasons.append(error)
                continue
            assert approval is not None
            if approval["key_id"] in key_ids:
                reasons.append(f"approval_{approval['key_id']}_duplicate_key")
                continue
            key_ids.add(approval["key_id"])
            approvals.append(approval)
        approvals.sort(
            key=lambda item: (
                item["role"],
                item["principal"],
                item["key_id"],
                item["approved_at"],
            )
        )

        approved_roles = {approval["role"] for approval in approvals}
        for role in required_roles:
            if role not in approved_roles:
                reasons.append(f"approval_role_{role}_missing")

        required_candidates = [
            approval for approval in approvals if approval["role"] in required_roles
        ]
        selected_approvals = self._select_independent_approvals(
            approvals, required_roles
        )
        if all(role in approved_roles for role in required_roles):
            required_principals = {
                approval["principal"] for approval in required_candidates
            }
            required_keys = {approval["key_id"] for approval in required_candidates}
            if len(required_principals) < len(required_roles):
                reasons.append("dual_key_requires_distinct_principals")
            if len(required_keys) < len(required_roles):
                reasons.append("dual_key_requires_distinct_keys")
            if selected_approvals is None:
                reasons.append("required_role_approvals_not_independent")

        evidence_body = {
            "now": now,
            "command": command,
            "required_channels": list(required_channels),
            "min_freshness": min_freshness,
            "telemetry": telemetry,
            "required_roles": list(required_roles),
            "approval_ttl_s": approval_ttl_s,
            "approvals": approvals,
        }
        computed_evidence_digest = _digest(evidence_body)
        expected_evidence_raw = req.payload.get("evidence_digest")
        expected_evidence_digest: str | None = None
        if expected_evidence_raw is not None:
            if not isinstance(expected_evidence_raw, str):
                reasons.append("evidence_digest_type_invalid")
            else:
                expected_evidence_digest = expected_evidence_raw.lower()
                if not _SHA256.fullmatch(expected_evidence_digest):
                    reasons.append("evidence_digest_invalid")
                elif expected_evidence_digest != computed_evidence_digest:
                    reasons.append("evidence_digest_mismatch")

        work_units = (
            self.BASE_WORK_UNITS
            + len(telemetry) * self.TELEMETRY_WORK_UNITS
            + len(approvals) * self.APPROVAL_WORK_UNITS
        )
        required_samples = [
            by_channel[channel] for channel in required_channels if channel in by_channel
        ]
        min_observed_freshness = min(
            (sample["freshness"] for sample in required_samples), default=0.0
        )
        selected = list(selected_approvals or ())
        result = {
            "schema": "glaciereq.telemetry-half-life.v1",
            "subject_id": subject_id,
            "grant_id": grant_id,
            "not_after": not_after,
            "now": now,
            "command": command,
            "required_channels": list(required_channels),
            "min_freshness": min_freshness,
            "telemetry": telemetry,
            "required_roles": list(required_roles),
            "approval_ttl_s": approval_ttl_s,
            "approvals": approvals,
            "selected_approvals": selected,
            "evidence_digest": computed_evidence_digest,
            "expected_evidence_digest": expected_evidence_digest,
            "eligible": not reasons,
        }
        decision = Decision.REFUSE if reasons else Decision.ALLOW
        if not reasons:
            reasons = ["fresh_telemetry_and_independent_approvals_verified"]
        selected_principals = {approval["principal"] for approval in selected}
        selected_keys = {approval["key_id"] for approval in selected}
        metrics = {
            "required_channel_count": len(required_channels),
            "telemetry_count": len(telemetry),
            "approval_count": len(approvals),
            "selected_approval_count": len(selected),
            "distinct_principals": len(selected_principals),
            "distinct_keys": len(selected_keys),
            "min_observed_freshness": min_observed_freshness,
            "work_units": work_units,
            "budget_units": budget,
            "evidence_digest_verified": expected_evidence_digest is None
            or expected_evidence_digest == computed_evidence_digest,
        }
        digest = _digest(
            {
                "decision": decision.value,
                "reasons": reasons,
                "result": result,
                "metrics": metrics,
            }
        )
        return CryoTelemetryHalfLifeReceipt(
            decision, tuple(reasons), digest, metrics, result
        )

    @staticmethod
    def _receipt(
        req: CryoTelemetryHalfLifeRequest,
        decision: Decision,
        reasons: Sequence[str],
        *,
        metrics: Mapping[str, Any] | None = None,
    ) -> CryoTelemetryHalfLifeReceipt:
        unique = tuple(dict.fromkeys(reasons))
        subject_id = req.subject_id.strip() if isinstance(req.subject_id, str) else ""
        result = {"subject_id": subject_id, "eligible": False}
        receipt_metrics = {
            "required_channel_count": 0,
            "telemetry_count": 0,
            "approval_count": 0,
        }
        receipt_metrics.update(dict(metrics or {}))
        digest = _digest(
            {
                "decision": decision.value,
                "reasons": list(unique),
                "result": result,
                "metrics": receipt_metrics,
            }
        )
        return CryoTelemetryHalfLifeReceipt(
            decision, unique, digest, receipt_metrics, result
        )


Mechanism = CryoTelemetryHalfLife


def _read_cli_input(path: str | None) -> str:
    limit = CryoTelemetryHalfLife.MAX_CLI_INPUT_CHARS
    if path:
        source = Path(path)
        if source.stat().st_size > limit * 4:
            raise ValueError("input_too_large")
        raw = source.read_text(encoding="utf-8")
    else:
        raw = sys.stdin.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("input_too_large")
    return raw


def cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate telemetry freshness and independent simulated-command approvals from JSON."
    )
    parser.add_argument("--input", "-i", help="request JSON file; defaults to stdin")
    args = parser.parse_args(argv)
    try:
        raw = _read_cli_input(args.input)
        data = json.loads(raw)
        if not isinstance(data, Mapping):
            raise ValueError("request JSON must be an object")
        payload_raw = data.get("payload", {})
        if not isinstance(payload_raw, Mapping):
            raise ValueError("payload must be an object")
        request = CryoTelemetryHalfLifeRequest(
            subject_id=data.get("subject_id", ""),
            payload=dict(payload_raw),
            budget=data.get("budget", 4.0),
            grant_id=data.get("grant_id"),
            not_after=data.get("not_after"),
        )
        receipt = CryoTelemetryHalfLife().evaluate(request)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "decision": "REFUSE",
                    "reasons": [f"cli_input_error:{type(exc).__name__}:{exc}"],
                },
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(receipt.as_dict(), indent=2, sort_keys=True))
    return 0 if receipt.decision is Decision.ALLOW else 2
