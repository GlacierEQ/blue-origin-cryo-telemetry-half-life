"""Cryogenic Propellant & Propulsion Telemetry — Core Module"""

import math
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class CryoTank:
    """Cryogenic propellant tank with boil-off dynamics."""
    volume_m3: float
    fill_fraction: float        # 0.0 to 1.0
    propellant_density: float   # kg/m^3 (LOX=1141, LCH4=422.6)
    boil_off_rate: float         # fraction per hour at ambient
    insulation_factor: float = 0.1  # 0=perfect, 1=no insulation

    @property
    def propellant_mass_kg(self) -> float:
        return self.volume_m3 * self.fill_fraction * self.propellant_density

    def mass_after_hours(self, hours: float, ambient_heat_w: float = 0.0) -> float:
        """Compute remaining propellant mass after boil-off.

        Uses exponential decay: m(t) = m0 * exp(-k*t)
        where k = boil_off_rate * insulation_factor
        """
        k = self.boil_off_rate * self.insulation_factor
        m0 = self.propellant_mass_kg
        return m0 * math.exp(-k * hours)

    def time_to_level(self, target_fraction: float) -> float:
        """Hours until tank reaches target fill fraction."""
        if target_fraction >= self.fill_fraction:
            return 0.0
        k = self.boil_off_rate * self.insulation_factor
        if k <= 0:
            return float('inf')
        ratio = target_fraction / self.fill_fraction
        return -math.log(ratio) / k


@dataclass
class EngineHealthTelemetry:
    """Real-time engine health monitoring."""
    chamber_pressure_psi: float
    turbopump_rpm: float
    nozzle_temp_k: float
    mixture_ratio: float  # oxidizer/fuel mass flow ratio
    thrust_kn: float

    NOMINAL_RANGES = {
        "chamber_pressure_psi": (2500.0, 3200.0),
        "turbopump_rpm": (30000.0, 38000.0),
        "nozzle_temp_k": (800.0, 1800.0),
        "mixture_ratio": (3.4, 3.8),
        "thrust_kn": (1800.0, 2300.0),
    }

    def anomalies(self) -> list[str]:
        """Return list of parameters outside nominal range."""
        issues = []
        for param, (lo, hi) in self.NOMINAL_RANGES.items():
            val = getattr(self, param)
            if val < lo or val > hi:
                issues.append(f"{{param}}={{val:.1f}} outside [{{lo}}, {{hi}}]")
        return issues

    @property
    def is_nominal(self) -> bool:
        return len(self.anomalies()) == 0

    @property
    def specific_impulse_s(self) -> float:
        """Approximate Isp from thrust and assumed mass flow."""
        # F = mdot * g0 * Isp -> Isp = F / (mdot * g0)
        # Raptor LOX/CH4: ~350s sea level
        g0 = 9.80665
        mdot_approx = self.thrust_kn * 1000.0 / (350.0 * g0)
        return self.thrust_kn * 1000.0 / (mdot_approx * g0)

