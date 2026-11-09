"""Stylised model of shadow IT growth with and without AI agents (Section 4).

Monthly recurrence, per employee (N = 1):

  adoption      A_t     = 1 - exp(-lam * t)
  classic       S_{t+1} = (1 - delta) S_t + kappa A_t
  agentic       X_{t+1} = (1 - delta) X_t + rho A_t + s X_t

kappa : unsanctioned tools acquired per adopter and per month (classic);
rho   : artifacts (scripts, automations, MCP servers...) created per agent
        user and per month;
s     : sigma * phi, artifacts created per month by the artifacts that are
        themselves agentic;
delta : share of unsanctioned artifacts retired per month (found and phased
        out, or abandoned).

The agentic stock grows exponentially when s > delta and converges to
rho / (delta - s) otherwise. All parameter values are ILLUSTRATIVE: they are
chosen to show the regimes, not fitted to data. Writes
results/tex/acceleration.dat for the figure. Standard library only.
"""

import math
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "results", "tex", "acceleration.dat")

LAM, KAPPA, RHO, DELTA = 0.10, 0.05, 0.50, 0.05
SCENARIOS = [
    ("classic", dict(rho=0.0, s=0.0, delta=DELTA, kappa=KAPPA)),
    ("subcritical", dict(rho=RHO, s=0.03, delta=DELTA, kappa=0.0)),
    ("supercritical", dict(rho=RHO, s=0.10, delta=DELTA, kappa=0.0)),
    ("detected", dict(rho=RHO, s=0.10, delta=0.15, kappa=0.0)),
]
MONTHS = 48


def run(rho, s, delta, kappa):
    x, out = 0.0, [0.0]
    for t in range(MONTHS):
        a = 1 - math.exp(-LAM * t)
        x = (1 - delta) * x + kappa * a + rho * a + s * x
        out.append(x)
    return out


def main():
    series = {name: run(**p) for name, p in SCENARIOS}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("month " + " ".join(name for name, _ in SCENARIOS) + "\n")
        for t in range(MONTHS + 1):
            f.write("%d %s\n" % (t, " ".join("%.4f" % max(series[n][t], 1e-3) for n, _ in SCENARIOS)))
    for name, _ in SCENARIOS:
        print("%-14s month 12: %8.2f   month 24: %8.2f   month 48: %8.2f" % (
            name, series[name][12], series[name][24], series[name][48]))


if __name__ == "__main__":
    main()
