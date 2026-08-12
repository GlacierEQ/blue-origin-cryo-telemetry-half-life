# Cryo Telemetry Half-Life

A vendor-neutral eligibility kernel for simulated command workflows that require fresh telemetry and independent approvals.

> Independent GlacierEQ implementation. Not affiliated with, endorsed by, employed by, or deployed at Blue Origin. It does not actuate hardware or claim flight use.

## Purpose

Telemetry-backed decisions become unsafe or meaningless when the underlying measurements outlive their useful freshness window. A command can also be over-authorized when one person or one key silently satisfies every required approval role.

Cryo Telemetry Half-Life converts those failure modes into deterministic, testable eligibility state before any separate executor or simulator is allowed to proceed.

## Capabilities

- explicit evaluation time for deterministic replay
- request-level expiry via `not_after`
- strict request/grant/telemetry/approval identity types; malformed JSON values are refused rather than string-coerced
- per-channel observation time and half-life
- quality-weighted exponential freshness: `quality × 0.5^(age / half_life)`
- explicit required telemetry channels
- configurable minimum freshness threshold
- refusal of missing, stale, duplicate, future-dated, malformed, or low-quality telemetry
- optional telemetry source SHA-256 identity
- explicit required approval roles
- approval time-to-live
- deterministic selection of one approval per required role such that every selected approval has a distinct key **and** distinct principal
- unrelated-role approvals cannot satisfy or pad the required-role independence invariant
- refusal of missing, duplicated, future-dated, expired, or non-independent approvals
- normalized evidence identity computed from command, telemetry, required channels, freshness policy, required roles, approval TTL, and approvals
- optional `evidence_digest` input is treated as an expected trusted digest and must match the computed evidence identity
- strict bounded JSON command/telemetry values
- collection caps and preflight work refusal before telemetry/approval normalization
- bounded CLI input before JSON parsing
- deterministic authorization receipts
- installable CLI

## Input

```json
{
  "subject_id": "simulation-command-1",
  "not_after": 1030.0,
  "budget": 4.0,
  "payload": {
    "now": 1000.0,
    "command": {"name": "simulation-stage-transition", "mode": "simulation"},
    "required_channels": ["tank.pressure", "tank.temperature"],
    "min_freshness": 0.5,
    "telemetry": [
      {"channel": "tank.pressure", "observed_at": 996.0, "half_life_s": 20.0, "quality": 1.0},
      {"channel": "tank.temperature", "observed_at": 997.0, "half_life_s": 20.0, "quality": 0.95}
    ],
    "required_roles": ["operator", "safety"],
    "approval_ttl_s": 30.0,
    "approvals": [
      {"key_id": "operator-key", "principal": "operator-a", "role": "operator", "approved_at": 998.0},
      {"key_id": "safety-key", "principal": "safety-b", "role": "safety", "approved_at": 999.0}
    ]
  }
}
```

Run:

```bash
cryo-telemetry-half-life --input request.json
```

Exit status is zero only when the declared command is eligible. The receipt includes normalized telemetry, all valid approvals, the independently selected required-role approvals, freshness metrics, the computed `evidence_digest`, refusal reasons, and a deterministic receipt digest.

### Bind a previously trusted evidence snapshot

First evaluate without `payload.evidence_digest` and retain the returned `result.evidence_digest`. A later candidate may provide that value as `payload.evidence_digest`. The evaluator recomputes evidence identity and refuses with `evidence_digest_mismatch` if command, telemetry, approval policy, or approvals have changed.

## Verify the repository

```bash
python -m pip install .
python -m pytest -q
python scripts/operate.py
```

The direct runtime smoke proves a fresh independently approved simulation command is eligible, the computed evidence digest can be re-verified, stale required telemetry is refused, unrelated approvals cannot mask reuse of one required-role principal, and evidence mutation invalidates an old expected digest.

## Safety and integration boundary

This repository **does not issue physical commands**. It only evaluates a normalized request and produces `ALLOW`/`REFUSE` eligibility. Any hardware, vehicle, facility, or mission executor remains a separate system with its own authenticated interfaces, physical safety interlocks, certified procedures, and human authority. This package is appropriate for local simulation, software testing, and generic freshness-policy evaluation.
