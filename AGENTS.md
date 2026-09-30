# AGENTS.md — blue-origin-cryo-telemetry-half-life

**Company:** Blue Origin
**Domain:** Cryogenic Propellant & Propulsion Telemetry

## Quick Rules
- **Test command:** `PYTHONPATH=src pytest tests/ -v`
- **Lint:** `ruff check src/ tests/`
- **No drive-by edits** — load the skill first.

## Architecture
- `src/blue_origin_cryo_telemetry_half_life/core.py` — Domain logic (Cryogenic Propellant & Propulsion Telemetry)
- `tests/` — Verified test suite
- `.github/workflows/ci.yml` — Enforced CI pipeline
