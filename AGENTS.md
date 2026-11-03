# AGENTS.md — blue-origin-cryo-telemetry-half-life

**Company:** Blue Origin
**Domain:** Cryogenic Propellant & Propulsion Telemetry

## Epistemology

- L0 (Presence): Verified — modules importable.
- L1 (Structure): Verified — public classes/functions present.
- L2 (Behavior): Verified — 30 tests pass, ruff clean, `scripts/operate.py` exits 0.
- Aspirational (L0/L1 only): hardware actuation, flight use, external deployment, affiliation claims.

## Quick Rules
- **Test command:** `PYTHONPATH=src pytest tests/ -v`
- **Lint:** `ruff check src/ tests/`
- **No drive-by edits** — load the skill first.

## Architecture
- `src/blue_origin_cryo_telemetry_half_life/core.py` — Domain logic (Cryogenic Propellant & Propulsion Telemetry)
- `tests/` — Verified test suite (30 tests: 7 cryo tank, 19 telemetry half-life, 4 impact assurance)
- `.github/workflows/ci.yml` — Enforced CI pipeline
