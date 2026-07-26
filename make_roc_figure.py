"""ROC curves of RS' vs the CVSS+AV baseline on the primary dataset.
Saves roc_figure.pdf (IEEE column width), marking the T=0.49 operating
point. Usage: python3 make_roc_figure.py
"""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from soc_chatbot import load_alerts, is_correlated, risk_score


def roc_points(scores, labels):
    pairs = sorted(zip(scores, labels), key=lambda x: -x[0])
    P = sum(labels); N = len(labels) - P
    pts, tp, fp = [(0.0, 0.0)], 0, 0
    for s, y in pairs:
        if y: tp += 1
        else: fp += 1
        pts.append((fp / N, tp / P))
    # trapezoidal AUC
    auc = sum((x2 - x1) * (y1 + y2) / 2
              for (x1, y1), (x2, y2) in zip(pts, pts[1:]))
    return pts, auc


def main():
    alerts = load_alerts("alerts.csv")
    corrs = {a["ID"]: is_correlated(a, alerts) for a in alerts}
    y = [1 if a["Criticality"] in ("High", "Critical") else 0 for a in alerts]

    rs = [risk_score(a, corrs[a["ID"]]) for a in alerts]
    cv = [(a["CVSS"] / 10 + a["AssetValue"] / 10) / 2 for a in alerts]

    (rs_pts, rs_auc) = roc_points(rs, y)
    (cv_pts, cv_auc) = roc_points(cv, y)

    # operating point of RS' at T = 0.49
    tp = sum(1 for s, t in zip(rs, y) if s >= 0.49 and t)
    fp = sum(1 for s, t in zip(rs, y) if s >= 0.49 and not t)
    P = sum(y); N = len(y) - P
    op = (fp / N, tp / P)

    fig, ax = plt.subplots(figsize=(3.45, 2.9))
    ax.plot(*zip(*rs_pts), lw=1.8, color="#1a5fb4",
            label=f"RS$'$ (AUC = {rs_auc:.3f})")
    ax.plot(*zip(*cv_pts), lw=1.5, color="#c01c28", ls="--",
            label=f"CVSS+AV (AUC = {cv_auc:.3f})")
    ax.plot([0, 1], [0, 1], color="0.6", lw=0.8, ls=":")
    ax.plot(*op, marker="o", ms=6, color="#1a5fb4", mec="black", mew=0.6)
    ax.annotate("$T=0.49$\n(R = 1.000)", op, textcoords="offset points",
                xytext=(8, -18), fontsize=7)
    ax.set_xlabel("False-positive rate", fontsize=8)
    ax.set_ylabel("True-positive rate", fontsize=8)
    ax.tick_params(labelsize=7)
    ax.set_xlim(-0.02, 1.0); ax.set_ylim(0.0, 1.02)
    ax.legend(fontsize=7, loc="lower right", frameon=False)
    ax.grid(alpha=0.25, lw=0.4)
    fig.tight_layout()
    fig.savefig("roc_figure.pdf")
    print(f"[OK] roc_figure.pdf  |  RS' AUC={rs_auc:.3f}  CVSS+AV AUC={cv_auc:.3f}  "
          f"operating point FPR={op[0]:.3f} TPR={op[1]:.3f}")


if __name__ == "__main__":
    main()
