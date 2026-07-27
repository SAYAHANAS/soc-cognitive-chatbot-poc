"""Cost of extending the safety floor to lower-severity classes.

The floor protects alerts rated High or Critical, so attack classes whose
public severity falls in the Medium band get no structural protection.
This sweeps the protected set and reports, on official benchmark records,
how many labelled attacks are still missed and how many benign records are
escalated at each setting.

Usage:
  python3 floor_tradeoff.py unsw   UNSW_NB15_training-set.csv
  python3 floor_tradeoff.py cicids "CIC2017\\Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
  (add a third argument to sample instead of using all records)
"""

import sys

from soc_chatbot import CRIT_ORDER, CRIT_SCORE
from real_data_eval import load_real, _fast_correlations

SETTINGS = [
    ("Critical only", 3, {"Critical": 0.60}),
    ("High+Critical (paper)", 2, {"Critical": 0.60, "High": 0.50}),
    ("Medium and above", 1, {"Critical": 0.60, "High": 0.50, "Medium": 0.50}),
    ("All (no suppression)", 0, {"Critical": 0.60, "High": 0.50,
                                 "Medium": 0.50, "Low": 0.50}),
]


def score(alert, correlated, floors):
    level = alert.get("Criticality", "Low")
    rs = (alert["CVSS"] / 10.0 + alert["AssetValue"] / 10.0
          + (1.0 if alert["History"] else 0.0)
          + CRIT_SCORE.get(level, 0.25)) / 4.0
    if level in floors:
        rs = max(rs, floors[level])
    if correlated:
        rs = min(1.0, rs + 0.15)
    return rs


def sweep(alerts, name, T=0.49):
    corrs = _fast_correlations(alerts)
    n_mal = sum(1 for a in alerts if a["_malicious"])
    n_ben = len(alerts) - n_mal
    print(f"\n{'='*72}\n  PROTECTED-CLASS TRADE-OFF  |  {name}"
          f"\n  N={len(alerts):,}  attacks={n_mal:,}  benign={n_ben:,}  T={T}\n{'='*72}")
    print(f"  {'protected set':24s} {'missed':>10s} {'recall':>8s} "
          f"{'benign esc.':>12s} {'esc. rate':>10s}")
    rows = []
    for label, _, floors in SETTINGS:
        fn = fp = 0
        for a in alerts:
            esc = score(a, corrs[a["ID"]], floors) >= T
            if a["_malicious"] and not esc:
                fn += 1
            elif not a["_malicious"] and esc:
                fp += 1
        rec = (n_mal - fn) / n_mal if n_mal else 0.0
        rate = fp / n_ben if n_ben else 0.0
        rows.append((label, fn, rec, fp, rate))
        print(f"  {label:24s} {fn:10,d} {rec:8.4f} {fp:12,d} {rate*100:9.1f}%")

    base = rows[1]
    for label, fn, rec, fp, rate in rows[2:]:
        d_fn, d_fp = base[1] - fn, fp - base[3]
        if d_fn > 0:
            print(f"\n  '{label}' vs paper setting: {d_fn:,} fewer missed attacks, "
                  f"{d_fp:,} more benign escalations "
                  f"({d_fp / d_fn:.1f} extra escalations per attack recovered)")
    return rows


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] not in ("unsw", "cicids"):
        print(__doc__)
        sys.exit(1)
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    alerts = load_real(sys.argv[1], sys.argv[2], n=n, seed=42)
    sweep(alerts, sys.argv[2])
