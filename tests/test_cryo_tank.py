"""Auto-generated tests for Cryogenic Propellant & Propulsion Telemetry."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from blue_origin_cryo_telemetry_half_life.core import CryoTank, EngineHealthTelemetry


def test_initial_mass():
    tank = CryoTank(volume_m3=100.0, fill_fraction=0.95,
                    propellant_density=1141.0, boil_off_rate=0.005)
    assert abs(tank.propellant_mass_kg - 100.0 * 0.95 * 1141.0) < 0.01

def test_boiloff_decreases_mass():
    tank = CryoTank(volume_m3=50.0, fill_fraction=1.0,
                    propellant_density=422.6, boil_off_rate=0.01)
    m0 = tank.propellant_mass_kg
    m1 = tank.mass_after_hours(10.0)
    assert m1 < m0

def test_perfect_insulation_no_loss():
    tank = CryoTank(volume_m3=50.0, fill_fraction=1.0,
                    propellant_density=422.6, boil_off_rate=0.01,
                    insulation_factor=0.0)
    m0 = tank.propellant_mass_kg
    m1 = tank.mass_after_hours(100.0)
    assert abs(m1 - m0) < 0.001

def test_time_to_level():
    tank = CryoTank(volume_m3=100.0, fill_fraction=1.0,
                    propellant_density=1141.0, boil_off_rate=0.01)
    t = tank.time_to_level(0.5)
    assert t > 0.0
    remaining = tank.mass_after_hours(t) / tank.propellant_mass_kg
    assert abs(remaining - 0.5) < 0.01

def test_engine_nominal():
    eng = EngineHealthTelemetry(
        chamber_pressure_psi=2900.0, turbopump_rpm=34000.0,
        nozzle_temp_k=1200.0, mixture_ratio=3.6, thrust_kn=2100.0)
    assert eng.is_nominal
    assert len(eng.anomalies()) == 0

def test_engine_anomaly_detection():
    eng = EngineHealthTelemetry(
        chamber_pressure_psi=1000.0, turbopump_rpm=34000.0,
        nozzle_temp_k=1200.0, mixture_ratio=3.6, thrust_kn=2100.0)
    assert not eng.is_nominal
    assert any("chamber_pressure" in a for a in eng.anomalies())

def test_specific_impulse_range():
    eng = EngineHealthTelemetry(
        chamber_pressure_psi=2900.0, turbopump_rpm=34000.0,
        nozzle_temp_k=1200.0, mixture_ratio=3.6, thrust_kn=2100.0)
    assert 300.0 < eng.specific_impulse_s < 400.0

