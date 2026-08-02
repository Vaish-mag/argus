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


def _load_metric(path: Path, col: str = "mttr", trials_only: bool = True) -> list[float]:
    """
    Read one timing column.

    `trials_only` drops unattributed detections (no attack marker, so recorded as false
    positives). Those are real heals, but they are not trials: including their durations
    in the timing distributions mixes two different populations and makes this script
    disagree with any other view of the same data. They are counted separately and
    reported as a false-positive line instead.
    """
    if not path.exists():
        return []
    out = []
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            if trials_only and r.get("false_positive") == "True":
                continue
            v = r.get(col)
            if v not in ("", "None", None):
                out.append(float(v))
    return out


def _count_unattributed(path: Path) -> int:
    if not path.exists():
        return 0
    with open(path, newline="") as fh:
        return sum(1 for r in csv.DictReader(fh) if r.get("false_positive") == "True")


def _load_col(path: Path, col: str) -> list[str]:
    if not path.exists():
        return []
    with open(path, newline="") as fh:
        return [r[col] for r in csv.DictReader(fh) if r.get(col)]


def main() -> None:
    results = Path("results")
    argus_csv = results / "incidents.csv"
    base_csv = results / "incidents_baseline.csv"

    argus_mttr = _load_metric(argus_csv, "mttr")
    base_mttr = _load_metric(base_csv, "mttr")
    if not argus_mttr:
        sys.exit("no Argus incidents found -- run the experiment first")

    def _outlier_note(label: str, vals: list[float]) -> list[str]:
        """
        Flag values far above the median.

        A single stalled trial (a starved or suspended VM keeps wall-clock running while
        the container does nothing) can be orders of magnitude larger than the rest and
        will wreck any mean. Surfacing it explicitly is the difference between reporting a
        nonsensical headline and reporting a measurement artefact you understood.
        """
        if len(vals) < 3:
            return []
        med = statistics.median(vals)
        bad = [v for v in vals if med > 0 and v > 10 * med]
        if not bad:
            return []
        return [
            f"    !! {len(bad)} outlier(s) in Argus {label}: max={max(bad):.0f}s vs "
            f"median={med:.2f}s.",
            "       That ratio is not controller behaviour -- it is almost certainly an",
            "       environment stall (VM starved of RAM, host suspended). Re-run on an",
            "       idle machine, or exclude and state that you did.",
        ]

    def _compare(label: str, a_vals: list[float], b_vals: list[float]) -> list[str]:
        out = []
        a_mean, a_med = statistics.mean(a_vals), statistics.median(a_vals)
        out.append(f"Argus {label}:    n={len(a_vals)} mean={a_mean:.2f}s median={a_med:.2f}s")
        if b_vals:
            b_mean, b_med = statistics.mean(b_vals), statistics.median(b_vals)
            out.append(f"Baseline {label}: n={len(b_vals)} mean={b_mean:.2f}s "
                       f"median={b_med:.2f}s")
            # Median first, deliberately: it is robust to a single stalled trial, and it is
            # the statistic consistent with the rank-based Mann-Whitney test reported below.
            if b_med:
                out.append(f"==> {label} reduction (median, quote this): "
                           f"{100 * (b_med - a_med) / b_med:.1f}%")
            if b_mean:
                out.append(f"    {label} reduction (mean, outlier-sensitive): "
                           f"{100 * (b_mean - a_mean) / b_mean:.1f}%")
            try:
                from scipy.stats import mannwhitneyu
                u, p = mannwhitneyu(a_vals, b_vals, alternative="less")
                out.append(f"    Mann-Whitney U={u:.1f}, p={p:.4g} (Argus < baseline)")
            except ImportError:
                out.append("    (install scipy for the Mann-Whitney U significance test)")
        out += _outlier_note(label, a_vals)
        return out

    lines = _compare("MTTR", argus_mttr, base_mttr)
    lines.append("  note: MTTR starts at DETECTION, so the manual arm's operator-notice")
    lines.append("  delay sits in MTTD and cancels out here. See total recovery below.")

    # End-to-end attack -> healthy again. This is the comparison that includes the human
    # notice delay the controller removes, so it is the headline resilience result.
    argus_total = _load_metric(argus_csv, "total_recovery")
    base_total = _load_metric(base_csv, "total_recovery")
    if argus_total:
        lines.append("")
        lines += _compare("TotalRecovery(attack->healthy)", argus_total, base_total)

    argus_mttd_vals = _load_metric(argus_csv, "mttd")
    if argus_mttd_vals:
        lines.append("")
        lines.append(f"Argus MTTD:    n={len(argus_mttd_vals)} "
                     f"mean={statistics.mean(argus_mttd_vals):.2f}s "
                     f"median={statistics.median(argus_mttd_vals):.2f}s")
    if base_csv.exists():
        base_mttd = _load_metric(base_csv, "mttd")
        if base_mttd:
            lines.append(f"Baseline MTTD: n={len(base_mttd)} "
                         f"mean={statistics.mean(base_mttd):.2f}s (modelled notice delay)")

    # Detections with no attack marker: real heals, but not trials. Excluded from the
    # timing distributions above and reported here so the exclusion is visible.
    unattributed = _count_unattributed(argus_csv)
    if unattributed:
        lines.append("")
        lines.append(f"Unattributed detections (excluded from the timings above): "
                     f"{unattributed}")
        lines.append("  These fired with no injected attack -- discuss them as false")
        lines.append("  positives, not as recovery measurements.")

    # A baseline trial whose health check never passed records no MTTR and silently
    # drops out of the comparison. Since those are the SLOWEST recoveries, dropping them
    # flatters the manual arm and understates the controller's advantage -- so say so.
    base_total_rows = 0
    if base_csv.exists():
        with open(base_csv, newline="") as fh:
            base_total_rows = sum(1 for _ in csv.DictReader(fh))
    if base_total_rows and len(base_mttr) < base_total_rows:
        lines.append("")
        lines.append(f"!! Baseline: only {len(base_mttr)} of {base_total_rows} trials "
                     f"recovered healthily.")
        lines.append("   The rest never passed their health check and are excluded. Those")
        lines.append("   are the slowest recoveries, so this UNDERSTATES the improvement.")
        lines.append("   Raise health_retries in config/argus.yaml and re-run the arm.")

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

    # --- fig 1b: end-to-end recovery comparison (the headline figure) ---
    if argus_total and base_total:
        plt.figure()
        names = ["Argus", "Static baseline"]
        try:
            plt.boxplot([argus_total, base_total], tick_labels=names)
        except TypeError:
            plt.boxplot([argus_total, base_total], labels=names)
        plt.ylabel("attack -> healthy again (seconds)")
        plt.title("End-to-end recovery time (includes operator-notice delay)")
        plt.savefig(results / "fig_total_recovery.png", dpi=150, bbox_inches="tight")

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
