#!/usr/bin/env python3
"""VEARL - Prototype 0: economic simulation (stdlib only).

Deliberately simple model, WITHOUT any promise of profitability. All the parameters are
HYPOTHESES to be replaced by measurements (see proto1_gpu for the hardware).

Strict separation (see master prompt, section 9):
  BLOCK REWARD = protocol emission -> pays for the security of the network (Native Work)
  COMPUTE FEE  = client payment    -> pays for the useful work

"Time-sharing" modelling hypothesis: a GPU does EITHER Native Work (security),
OR a client job. Native Work is therefore only secured by the GPUs that are not busy.
A design where the same work serves both (real PoUW) is a RESEARCH NEEDED point.

Equilibrium: GPUs enter as long as the average revenue per GPU-hour > cost per GPU-hour.
"""
from dataclasses import dataclass
import argparse


@dataclass
class Params:
    block_time_s: float = 60.0
    reward0: float = 20.0            # tokens / block at t=0 (PROVISIONAL)
    halflife_years: float = 2.0      # smooth exponential decay (PROVISIONAL)
    tail_emission_frac: float = 0.01  # floor = 1 % of reward0 (tail emission, PROVISIONAL)
    token_price_usd: float = 0.10
    gpu_power_kw: float = 0.20        # ~ A10 under load (measured: ~151 W under a GPU miner)
    elec_usd_kwh: float = 0.10
    gpu_capex_usd_h: float = 0.15     # hardware depreciation per hour
    compute_price_usd_gpuh: float = 0.35  # client price per GPU-hour
    protocol_fee: float = 0.02        # share of the compute fee burned/treasury
    demand_gpu_hours_per_h: float = 0.0   # client demand, in GPU-hours per hour


def reward_per_block(p: Params, years: float) -> float:
    decay = 0.5 ** (years / p.halflife_years)
    return max(p.reward0 * decay, p.reward0 * p.tail_emission_frac)


def equilibrium(p: Params, years: float):
    blocks_per_h = 3600 / p.block_time_s
    emission_usd_h = reward_per_block(p, years) * blocks_per_h * p.token_price_usd
    cost_gpu_h = p.gpu_power_kw * p.elec_usd_kwh + p.gpu_capex_usd_h

    # The GPUs serving the clients earn the compute price (net of fee) IF it covers their cost.
    net_price = p.compute_price_usd_gpuh * (1 - p.protocol_fee)
    serving = p.demand_gpu_hours_per_h if net_price > cost_gpu_h else 0.0
    compute_rev_h = serving * net_price

    # The mining GPUs share the emission; equilibrium = total cost covered.
    miners = emission_usd_h / cost_gpu_h            # native GPUs at equilibrium (profit ~ 0)
    total_gpus = miners + serving
    honest_security_gpus = miners                   # only these secure the consensus
    attack_cost_h = 0.51 * honest_security_gpus * cost_gpu_h * 2.0  # 51 % + rental margin x2 (hypothesis)
    return dict(
        years=years, emission_usd_h=emission_usd_h, compute_rev_h=compute_rev_h,
        miners=miners, serving=serving, total_gpus=total_gpus,
        attack_cost_usd_h=attack_cost_h, cost_gpu_h=cost_gpu_h,
        emission_tokens_day=reward_per_block(p, years) * blocks_per_h * 24,
        compute_share=compute_rev_h / (compute_rev_h + emission_usd_h) if (compute_rev_h + emission_usd_h) else 0,
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--years", type=float, nargs="*", default=[0, 2, 4, 8])
    a = ap.parse_args()

    markets = {"empty": 0.0, "low": 50.0, "medium": 500.0, "saturated": 5000.0}
    prices = {"drop x0.1": 0.01, "base": 0.10, "blows up x10": 1.00}
    print("| market | token price | year | native GPUs | client GPUs | emission $/h | fees $/h | compute share | 51 % attack cost $/h |")
    print("|---|---|---|---|---|---|---|---|---|")
    for mname, d in markets.items():
        for pname, pr in prices.items():
            for y in a.years:
                r = equilibrium(Params(demand_gpu_hours_per_h=d, token_price_usd=pr), y)
                print(f"| {mname} | {pname} | {y:g} | {r['miners']:.0f} | {r['serving']:.0f} | "
                      f"{r['emission_usd_h']:.1f} | {r['compute_rev_h']:.1f} | {r['compute_share']:.0%} | {r['attack_cost_usd_h']:.0f} |")

    print("\nElectricity sensitivity (medium market, base price, year 0):")
    for kwh in (0.03, 0.10, 0.25):
        r = equilibrium(Params(demand_gpu_hours_per_h=500, elec_usd_kwh=kwh), 0)
        print(f"  {kwh:.2f} $/kWh -> cost/GPU-h {r['cost_gpu_h']:.3f} $, native GPUs {r['miners']:.0f}")

    print("\nReading: security (attack cost) depends ONLY on the emission x token price;")
    print("the clients do not contribute to it in this time-sharing model. This is the central problem to")
    print("solve (see docs/00: hybrid Native Work + useful-computation proof).")


if __name__ == "__main__":
    main()
