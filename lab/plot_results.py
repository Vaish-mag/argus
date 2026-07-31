#!/usr/bin/env python3
"""
plot_results.py -- generates the figures the Results chapter needs.
==================================================================
Reads results/incidents.csv (Argus arm) and results/incidents_baseline.csv (control arm)
and writes:
  results/fig_mttr_comparison.png   grouped bar / box: Argus vs baseline MTTR
  results/fig_mttd_hist.png         MTTD distribution (Argus)
  results/fig_detection_source.png  detections by source (signature/anomaly/both)
  results/summary.txt               the numbers to quote, incl. % MTTR reduction

Also prints the headline hypothesis-test line:
  "self-healing MTD reduced mean MTTR by X% vs the static baseline (p=...)"
and runs a Mann-Whitney U test (non-parametric, no normality assumption) if scipy present.

Usage:  python lab/plot_results.py
"""
from __future__ import annotations

import csv
import statistics
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


def _load_mttr(path: Path) -> list[float]:
    if not path.exists():
        return []
    out = []
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            v = r.get("mttr")
            if v not in ("", "None", None):
                out.append(float(v))
    return out


def _load_col(path: Path, col: str) -> list[str]:
    if not path.exists():
        return []
    with open(path, newline="") as fh:
        return [r[col] for r in csv.DictReader(fh) if r.get(col)]


def main() -> None:
    results = Path("results")
    argus_csv = results / "incidents.csv"
    base_csv = results / "incidents_baseline.csv"

    argus_mttr = _load_mttr(argus_csv)
    base_mttr = _load_mttr(base_csv)
    if not argus_mttr:
        sys.exit("no Argus incidents found -- run the experiment first")

    lines = []
    a_mean = statistics.mean(argus_mttr)
    lines.append(f"Argus MTTR:    n={len(argus_mttr)} mean={a_mean:.2f}s "
                 f"median={statistics.median(argus_mttr):.2f}s")
    if base_mttr:
        b_mean = statistics.mean(base_mttr)
        reduction = 100 * (b_mean - a_mean) / b_mean
        lines.append(f"Baseline MTTR: n={len(base_mttr)} mean={b_mean:.2f}s "
                     f"median={statistics.median(base_mttr):.2f}s")
        lines.append(f"==> MTTR reduction: {reduction:.1f}%")
        try:
            from scipy.stats import mannwhitneyu
            u, p = mannwhitneyu(argus_mttr, base_mttr, alternative="less")
            lines.append(f"Mann-Whitney U={u:.1f}, p={p:.4g} (Argus < baseline)")
        except ImportError:
            lines.append("(install scipy for the Mann-Whitney U significance test)")

    (results / "summary.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))

    # --- fig 1: MTTR comparison box plot ---
    if base_mttr:
        plt.figure()
        names = ["Argus", "Static baseline"]
        try:                                   # matplotlib >= 3.9 renamed the kwarg
            plt.boxplot([argus_mttr, base_mttr], tick_labels=names)
        except TypeError:
            plt.boxplot([argus_mttr, base_mttr], labels=names)
        plt.ylabel("MTTR (seconds)")
        plt.title("Mean-Time-To-Recover: self-healing MTD vs static baseline")
        plt.savefig(results / "fig_mttr_comparison.png", dpi=150, bbox_inches="tight")

    # --- fig 2: MTTD histogram ---
    argus_mttd = [float(v) for v in _load_col(argus_csv, "mttd")
                  if v not in ("", "None")]
    if argus_mttd:
        plt.figure()
        plt.hist(argus_mttd, bins=12)
        plt.xlabel("MTTD (seconds)"); plt.ylabel("count")
        plt.title("Argus detection latency distribution")
        plt.savefig(results / "fig_mttd_hist.png", dpi=150, bbox_inches="tight")

    # --- fig 3: detection source breakdown ---
    sources = _load_col(argus_csv, "detected_by")
    if sources:
        labels = sorted(set(sources))
        counts = [sources.count(l) for l in labels]
        plt.figure()
        plt.bar(labels, counts)
        plt.ylabel("detections"); plt.title("Detections by evidence source")
        plt.savefig(results / "fig_detection_source.png", dpi=150, bbox_inches="tight")

    print(f"\nfigures written to {results}/")


if __name__ == "__main__":
    main()
