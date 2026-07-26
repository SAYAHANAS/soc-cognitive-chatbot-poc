"""Evaluate the pipeline on the official UNSW-NB15 / CICIDS-2017 records.

Reads the published benchmark CSVs, maps each record's attack category to
the SOC alert schema (same mapping tables as the paper), and evaluates
Naive / CVSS+AV / RS' against the dataset's own malicious/benign label.

Data:
  UNSW-NB15   : UNSW_NB15_training-set.csv
                https://research.unsw.edu.au/projects/unsw-nb15-dataset
  CICIDS-2017 : MachineLearningCVE files
                https://www.unb.ca/cic/datasets/ids-2017.html

Usage:
  python3 real_data_eval.py unsw   UNSW_NB15_training-set.csv        [n] [seed]
  python3 real_data_eval.py cicids Wednesday-workingHours.pcap_ISCX.csv [n] [seed]
  (n = stratified sample size, 0 = all records; default 5000 / seed 42)
"""

import csv
import random
import sys
from datetime import datetime, timedelta

from soc_chatbot import (
    ASSETS, MITRE, HISTORY_NOTE, RECOMMENDATIONS, CRIT_SCORE,
    load_alerts, batch_score, triage_metrics, cohens_kappa, auc_roc,
    is_correlated, risk_score,
)

# ────────────────────────────────────────────────────────────────────────────
# Category -> (SOC alert type, NVD-median CVSS) — same tables as the paper.
# ────────────────────────────────────────────────────────────────────────────
UNSW_MAP = {
    # attack_cat -> (SOC type, NVD-median CVSS)
    "DoS":            ("BruteForce",       7.5),
    "Backdoor":       ("Malware",          9.8),
    "Backdoors":      ("Malware",          9.8),   # spelling varies per file
    "Worms":          ("Malware",          9.8),
    "Fuzzers":        ("Ransomware",       7.5),
    "Shellcode":      ("Ransomware",       9.8),
    "Exploits":       ("DataExfiltration", 8.8),
    "Generic":        ("Phishing",         5.3),
    "Reconnaissance": ("BruteForce",       5.3),
    "Analysis":       ("DataExfiltration", 6.5),
}

CICIDS_MAP = {
    # Label -> (SOC type, NVD-median CVSS)
    "DoS Hulk":                     ("BruteForce",       7.5),
    "DoS GoldenEye":                ("BruteForce",       7.5),
    "DoS slowloris":                ("BruteForce",       7.5),
    "DoS Slowhttptest":             ("BruteForce",       7.5),
    "DDoS":                         ("BruteForce",       7.5),
    "PortScan":                     ("BruteForce",       5.3),
    "FTP-Patator":                  ("BruteForce",       8.1),
    "SSH-Patator":                  ("BruteForce",       8.1),
    "Bot":                          ("Malware",          9.8),
    "Infiltration":                 ("DataExfiltration", 8.8),
    "Web Attack \u2013 Brute Force": ("DataExfiltration", 7.3),
    "Web Attack \u2013 XSS":         ("DataExfiltration", 9.1),
    "Web Attack \u2013 Sql Injection": ("DataExfiltration", 9.1),
    # ASCII-dash variants seen in some releases
    "Web Attack - Brute Force":     ("DataExfiltration", 7.3),
    "Web Attack - XSS":             ("DataExfiltration", 9.1),
    "Web Attack - Sql Injection":   ("DataExfiltration", 9.1),
    "Heartbleed":                   ("DataExfiltration", 9.8),
}


def _norm(label):
    """Match labels whatever happened to their dash. The CICIDS web-attack
    labels carry a CP1252 en-dash, and copies of the dataset in circulation
    have it re-encoded as U+FFFD or as the bytes EF BF BD. Keeping only
    ASCII alphanumerics makes all of those variants collapse to one key."""
    s = "".join(c if (c.isalnum() and c.isascii()) else " " for c in label.lower())
    return " ".join(s.split())


_CICIDS_NORM = {_norm(k): v for k, v in CICIDS_MAP.items()}
_UNSW_NORM = {_norm(k): v for k, v in UNSW_MAP.items()}


def _to_alert(i, soc_type, cvss, malicious, rng, ts):
    """One record in the alert schema. Criticality follows the CVSS band
    for malicious records, Low/Medium for benign; it is not used as
    ground truth here."""
    asset = rng.choice(list(ASSETS.keys()))
    if malicious:
        crit = ("Critical" if cvss >= 9.0 else "High" if cvss >= 7.0
                else "Medium" if cvss >= 4.0 else "Low")
    else:
        crit = rng.choices(["Low", "Medium"], weights=[0.4, 0.6])[0]
        cvss = 0.0
    has_hist = rng.random() > 0.40
    return {
        "ID": i, "Type": soc_type, "Criticality": crit,
        "Source": asset, "AssetValue": ASSETS[asset],
        "CVE": "None", "CVSS": round(cvss, 1),
        "History": has_hist,
        "HistoryNote": HISTORY_NOTE[soc_type][0] if has_hist else HISTORY_NOTE[soc_type][1],
        "MITRE_Code": MITRE[soc_type][0], "MITRE_Name": MITRE[soc_type][1],
        "Timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "Recommendations": RECOMMENDATIONS[soc_type],
        "_malicious": malicious,
    }


def load_real(kind, path, n=5000, seed=42):
    rng = random.Random(seed)
    rows = []
    types = list(MITRE.keys())
    unmapped = {}
    print(f"[..] reading {path}")
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        # normalise header whitespace (CICIDS headers have leading spaces)
        for rec in reader:
            rec = {k.strip(): v for k, v in rec.items() if k}
            if kind == "unsw":
                cat = (rec.get("attack_cat") or "").strip()
                lab = (rec.get("label") or "").strip()
                malicious = lab == "1"
                if malicious and _norm(cat) not in _UNSW_NORM:
                    unmapped[cat] = unmapped.get(cat, 0) + 1
                    continue
                soc_type, cvss = _UNSW_NORM.get(_norm(cat), ("BruteForce", 5.3))
            else:  # cicids
                lab = (rec.get("Label") or "").strip()
                malicious = lab.upper() != "BENIGN"
                key = _norm(lab)
                if malicious and key not in _CICIDS_NORM:
                    unmapped[lab] = unmapped.get(lab, 0) + 1
                    continue
                soc_type, cvss = _CICIDS_NORM.get(key, ("BruteForce", 5.3))
            if not malicious:
                soc_type = rng.choice(types)
                cvss = 0.0
            rows.append((soc_type, cvss, malicious))
            if len(rows) % 100000 == 0:
                print(f"[..] {len(rows):,} records parsed")
    if not rows:
        raise SystemExit(f"No usable records found in {path} — is this the "
                         f"official {'UNSW-NB15 train/test' if kind=='unsw' else 'MachineLearningCVE'} file?")

    # stratified sample preserving the file's own class balance
    if n and n < len(rows):
        mal = [r for r in rows if r[2]]
        ben = [r for r in rows if not r[2]]
        n_mal = round(n * len(mal) / len(rows))
        rows = rng.sample(mal, n_mal) + rng.sample(ben, n - n_mal)
        rng.shuffle(rows)

    if unmapped:
        print("[!!] unmapped attack labels (records skipped):")
        for lab, cnt in sorted(unmapped.items(), key=lambda x: -x[1]):
            print(f"     {cnt:>8,}  {lab!r}")
    print(f"[..] {len(rows):,} usable records, building alerts")
    base_ts = datetime(2024, 11, 1, 6, 0, 0)
    alerts = [
        _to_alert(i + 1, t, c, m, rng,
                  base_ts + timedelta(hours=rng.randint(0, 24 * 30),
                                      minutes=rng.randint(0, 59)))
        for i, (t, c, m) in enumerate(rows)
    ]
    return alerts


def _fast_correlations(alerts, window_min=60):
    """Same result as is_correlated for every alert, in O(n log n):
    group by source, sort timestamps, check nearest neighbours."""
    from datetime import datetime as _dt
    by_src = {}
    for a in alerts:
        try:
            t = _dt.strptime(a["Timestamp"], "%Y-%m-%d %H:%M:%S")
        except (ValueError, KeyError):
            continue
        by_src.setdefault(a["Source"], []).append((t, a["ID"]))
    corr = {a["ID"]: False for a in alerts}
    win = window_min * 60
    for src_alerts in by_src.values():
        src_alerts.sort()
        for i, (t, aid) in enumerate(src_alerts):
            if i > 0 and (t - src_alerts[i-1][0]).total_seconds() <= win:
                corr[aid] = True
            elif i + 1 < len(src_alerts) and (src_alerts[i+1][0] - t).total_seconds() <= win:
                corr[aid] = True
    return corr


def evaluate_real(alerts, name, T=0.49):
    """Naive / CVSS+AV / RS' against the dataset's own malicious label."""
    n_mal = sum(1 for a in alerts if a["_malicious"])
    print(f"\n{'='*68}\n  REAL-DATA EVALUATION  |  {name}  |  N={len(alerts)}  "
          f"malicious={n_mal} ({n_mal/len(alerts)*100:.1f}%)  T={T}\n{'='*68}")
    print("[..] scoring")
    corrs = _fast_correlations(alerts)

    def metrics(pred_fn, score_fn):
        tp = tn = fp = fn = 0
        for a in alerts:
            real, pred = a["_malicious"], pred_fn(a)
            if   real and pred:     tp += 1
            elif real and not pred: fn += 1
            elif not real and pred: fp += 1
            else:                   tn += 1
        N  = len(alerts)
        ta = (tp + tn) / N
        P  = tp / (tp + fp) if tp + fp else 0.0
        R  = tp / (tp + fn) if tp + fn else 0.0
        F1 = 2 * P * R / (P + R) if P + R else 0.0
        k, _, _ = cohens_kappa(dict(tp=tp, tn=tn, fp=fp, fn=fn, N=N, ta=ta))
        # AUC with proper handling of tied scores (Mann-Whitney form)
        pairs = sorted(((score_fn(a), 1 if a["_malicious"] else 0) for a in alerts),
                       key=lambda x: x[0])
        P_tot = sum(y for _, y in pairs); N_tot = len(pairs) - P_tot
        if P_tot and N_tot:
            i, rank_sum = 0, 0.0
            while i < len(pairs):
                j = i
                while j < len(pairs) and pairs[j][0] == pairs[i][0]:
                    j += 1
                avg_rank = (i + 1 + j) / 2.0          # average rank of the tie block
                rank_sum += avg_rank * sum(y for _, y in pairs[i:j])
                i = j
            auc = (rank_sum - P_tot * (P_tot + 1) / 2.0) / (P_tot * N_tot)
        else:
            auc = 0.0
        return ta, P, R, F1, k, auc, fn

    rows = [
        ("Naive",   lambda a: True,
                    lambda a: 1.0),
        ("CVSS+AV", lambda a: (a["CVSS"]/10 + a["AssetValue"]/10)/2 >= T,
                    lambda a: (a["CVSS"]/10 + a["AssetValue"]/10)/2),
        ("RS'",     lambda a: risk_score(a, corrs[a["ID"]]) >= T,
                    lambda a: risk_score(a, corrs[a["ID"]])),
    ]
    print(f"  {'Method':8s} {'TA':>7s} {'P':>6s} {'R':>6s} {'F1':>6s} "
          f"{'kappa':>6s} {'AUC':>6s} {'FN':>5s}")
    for label, pf, sf in rows:
        ta, P, R, F1, k, auc, fn = metrics(pf, sf)
        print(f"  {label:8s} {ta*100:6.1f}% {P:6.3f} {R:6.3f} {F1:6.3f} "
              f"{k:6.3f} {auc:6.3f} {fn:5d}")


def save_alerts(alerts, path):
    keys = [k for k in alerts[0] if k != "_malicious"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for a in alerts:
            w.writerow({k: a[k] for k in keys})
    print(f"[OK] {len(alerts)} alerts -> {path}")


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] not in ("unsw", "cicids"):
        print(__doc__)
        sys.exit(1)
    import os
    kind, path = sys.argv[1], sys.argv[2]
    n    = int(sys.argv[3]) if len(sys.argv) > 3 else 5000
    seed = int(sys.argv[4]) if len(sys.argv) > 4 else 42
    alerts = load_real(kind, path, n=n, seed=seed)
    stem = os.path.splitext(os.path.basename(path))[0].replace(".pcap_ISCX", "")
    save_alerts(alerts, f"real_{kind}_{stem}.csv")
    evaluate_real(alerts, f"{'UNSW-NB15' if kind=='unsw' else 'CICIDS-2017'} {stem} (official records)")
