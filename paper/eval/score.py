"""Scores the evaluation bench and writes the LaTeX tables and macros.

Reads, for each mode present (standard, admin):
  results/<mode>/runs/<id>/        complete runs of run-episodes.ps1 (run.json and
                                   episodes/*.json); detections are counted over
                                   the runs and the majority outcome is scored
  results/<mode>/overhead.jsonl    scan metrics (bench-overhead.ps1), optional
  results/<mode>/insitu.json       workstation scan (insitu.ps1), optional
  results/<mode>/dns-ttl.jsonl     DNS cache expiry (dns-ttl.ps1), optional
  results/<mode>/intermittent.jsonl  intermittent agent at random scan times
                                   (intermittent.ps1), optional
and writes:
  results/summary-<mode>.json
  results/tex/*.tex                tables and \\newcommand macros used by the paper

With --check, scores into a temporary folder and compares the result with
results/tex, so that a reader can verify the tables and values of the paper
from the published runs alone, without the raw scans that stay private.

Standard library only. Usage: python score.py [--check]
"""

import glob
import json
import math
import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results")
TEX = os.path.join(RESULTS, "tex")
SUMMARIES = RESULTS

DETECTORS = [
    ("D0", "Signature (process name)"),
    ("D1", "Behaviour (interpreter + TLS + shell)"),
    ("D2", "Behaviour (any process + TLS + shell)"),
    ("AD", "Agent Detector (multi-signal)"),
]
MODE_PREFIX = {"standard": "Std", "admin": "Adm"}

KIND_LABELS = {
    "network": "LLM endpoint",
    "behavior": "LLM + shell",
    "base-url": "base URL",
    "listener": "local LLM port",
    "module": "inference module",
    "mcp-server": "MCP server",
    "browser-automation": "automated browser",
    "env": "API key variable",
    "process": "process identity",
}


def load_json(path):
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)


def detected(ep, det):
    if det == "AD":
        return bool(ep["agent_detector"]["detected"])
    return bool(ep["baseline"][det])


def ratio(num, den):
    return None if den == 0 else num / den


def fmt(x, digits=2):
    return "n/a" if x is None else ("%.*f" % (digits, x))


def tex_escape(s):
    out = []
    for c in str(s):
        out.append({"\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "_": r"\_", "#": r"\#",
                    "$": r"\$", "~": r"\textasciitilde{}", "^": r"\textasciicircum{}",
                    "{": r"\{", "}": r"\}"}.get(c, c))
    return "".join(out)


DIGITS = ["Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine"]


def macro_name(prefix, *parts):
    # LaTeX macro names: letters only, so digits are spelled out.
    name = prefix + "".join(p[:1].upper() + p[1:] for p in parts)
    return "".join(DIGITS[int(c)] if c.isdigit() else c for c in name if c.isalnum())


def ad_signals(ep):
    kinds = set()
    for f in ep["agent_detector"]["findings"]:
        if f["confidence"] in ("medium", "high"):
            kinds.update(f["kinds"])
    return sorted(kinds)


def ad_label(ep):
    names = []
    for f in ep["agent_detector"]["findings"]:
        if f["confidence"] not in ("medium", "high"):
            continue
        tid = f["tool_id"]
        label = tid.split(":")[0]
        if label not in names:
            names.append(label)
    return ", ".join(names) if names else "--"


def clopper_pearson(x, n, alpha=0.05):
    """Exact two-sided confidence interval of a binomial proportion."""
    if n == 0:
        return None, None

    def cdf(k, p):  # P(X <= k)
        return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(0, k + 1))

    def solve(below):
        lo, hi = 0.0, 1.0
        for _ in range(60):
            mid = (lo + hi) / 2
            if below(mid):
                lo = mid
            else:
                hi = mid
        return (lo + hi) / 2

    lower = 0.0 if x == 0 else solve(lambda p: 1 - cdf(x - 1, p) < alpha / 2)
    upper = 1.0 if x == n else solve(lambda p: cdf(x, p) > alpha / 2)
    return lower, upper


def load_runs(mode):
    """Complete, non-partial runs of a mode (results/<mode>/runs/<id>/).

    Falls back to the single legacy run (results/<mode>/episodes/) when no run
    with provenance exists. Fails when a complete run misses an episode, so
    that a table can never mix runs."""
    runs = []
    for rj in sorted(glob.glob(os.path.join(RESULTS, mode, "runs", "*", "run.json"))):
        meta = load_json(rj)
        if not meta.get("complete") or meta.get("partial"):
            continue
        d = os.path.dirname(rj)
        eps = {}
        for f in glob.glob(os.path.join(d, "episodes", "*.json")):
            e = load_json(f)
            if e.get("run_id") not in (None, meta["run_id"]):
                raise SystemExit("episode %s does not belong to run %s" % (f, meta["run_id"]))
            eps[e["id"]] = e
        missing = [i for i in meta.get("episodes", []) if i not in eps]
        if missing:
            raise SystemExit("run %s is missing episodes %s" % (meta["run_id"], ", ".join(missing)))
        runs.append(dict(meta=meta, dir=d, episodes=eps))
    if runs:
        first = sorted(runs[0]["episodes"])
        if any(sorted(r["episodes"]) != first for r in runs):
            raise SystemExit("the runs of %s do not cover the same episodes" % mode)
        return runs
    legacy = os.path.join(RESULTS, mode, "episodes")
    if os.path.isdir(legacy):
        eps = {}
        for f in glob.glob(os.path.join(legacy, "*.json")):
            e = load_json(f)
            eps[e["id"]] = e
        return [dict(meta={"run_id": "legacy"}, dir=os.path.join(RESULTS, mode), episodes=eps)]
    return []


def aggregate(runs):
    """One record per episode: detections counted over the runs, majority outcome."""
    n = len(runs)
    out = []
    for eid in sorted(runs[0]["episodes"]):
        recs = [r["episodes"][eid] for r in runs]
        e0 = recs[0]
        counts = {d: sum(1 for x in recs if detected(x, d)) for d, _ in DETECTORS}
        labels = []
        for x in recs:
            for name in ad_label(x).split(", "):
                if name != "--" and name not in labels:
                    labels.append(name)
        out.append(dict(
            id=eid, label=e0["label"], scope=e0["scope"], cls=e0["class"], description=e0["description"],
            runs=n, counts=counts, detected={d: counts[d] * 2 > n for d in counts},
            ad_labels=labels, ad_signals=sorted({k for x in recs for k in ad_signals(x)}),
            background={d: sorted({b.lower() for x in recs for b in x.get("background", {}).get(d, [])})
                        for d in ("D0", "D1", "D2")}))
    return out


def task_metrics(eps, positive_labels):
    """Precision and recall on the main episodes: positives against benign workloads."""
    pos = [e for e in eps if e["scope"] == "main" and e["label"] in positive_labels]
    neg = [e for e in eps if e["scope"] == "main" and e["label"] == "benign"]
    metrics = {}
    for det, _ in DETECTORS:
        tp = sum(1 for e in pos if e["detected"][det])
        fn = len(pos) - tp
        fp = sum(1 for e in neg if e["detected"][det])
        tn = len(neg) - fp
        p, r = ratio(tp, tp + fp), ratio(tp, tp + fn)
        f1 = None if (p is None or r is None or p + r == 0) else 2 * p * r / (p + r)
        metrics[det] = dict(tp=tp, fn=fn, fp=fp, tn=tn, precision=p, recall=r, f1=f1,
                            precision_ci=clopper_pearson(tp, tp + fp), recall_ci=clopper_pearson(tp, tp + fn))
    return metrics


def cell(e, det):
    k, n = e["counts"][det], e["runs"]
    if k == n:
        return r"\cmark"
    if k == 0:
        return r"\xmark"
    return r"{\scriptsize %d/%d}" % (k, n)


GROUP_ORDER = {("main", "agent"): 0, ("main", "component"): 1, ("main", "benign"): 2, ("robustness", "agent"): 3}


def write_episode_table(mode, eps):
    lines = [r"\begin{tabular}{@{}l >{\raggedright\arraybackslash}p{2.4cm} >{\raggedright\arraybackslash}p{4.4cm} c c c c >{\raggedright\arraybackslash}p{3.0cm}@{}}", r"\toprule",
             r"Id & Class & Episode & D0 & D1 & D2 & AD & Agent Detector findings \\", r"\midrule"]
    last_group = None
    for e in sorted(eps, key=lambda x: (GROUP_ORDER.get((x["scope"], x["label"]), 9), x["id"])):
        group = (e["scope"], e["label"])
        if last_group is not None and group != last_group:
            lines.append(r"\midrule")
        last_group = group
        cells = [e["id"], tex_escape(e["cls"]), tex_escape(e["description"])]
        cells += [cell(e, d) for d, _ in DETECTORS]
        cells.append(tex_escape(", ".join(e["ad_labels"])) if e["ad_labels"] else "--")
        lines.append(" & ".join(cells) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    with open(os.path.join(TEX, "tab-episodes-%s.tex" % mode), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def fmt_ci(value, ci):
    if value is None:
        return "n/a"
    return r"%s {\scriptsize[%s, %s]}" % (fmt(value), fmt(ci[0]), fmt(ci[1]))


def write_metrics_table(mode, metrics, components):
    short = {"D0": "D0 signature", "D1": "D1 interpreter rule", "D2": "D2 any-process rule", "AD": "Agent Detector"}
    lines = [r"\begin{tabular}{@{}l r r r r l l r c@{}}", r"\toprule",
             r"Detector & TP & FN & FP & TN & Precision [95\% CI] & Recall [95\% CI] & F1 & Components \\",
             r"\midrule"]
    for det, _ in DETECTORS:
        m = metrics[det]
        lines.append("%s & %d & %d & %d & %d & %s & %s & %s & %d/%d \\\\" % (
            short[det], m["tp"], m["fn"], m["fp"], m["tn"],
            fmt_ci(m["precision"], m["precision_ci"]), fmt_ci(m["recall"], m["recall_ci"]), fmt(m["f1"]),
            components[det], components["total"]))
    lines += [r"\bottomrule", r"\end{tabular}"]
    with open(os.path.join(TEX, "tab-metrics-%s.tex" % mode), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def write_pr_data(mode, metrics):
    """One file per detector for the precision-recall figure, with the 95% intervals."""
    for det, _ in DETECTORS:
        m = metrics[det]
        path = os.path.join(TEX, "pr-%s-%s.dat" % (mode, det))
        if m["precision"] is None:
            if os.path.exists(path):
                os.remove(path)
            continue
        with open(path, "w", encoding="utf-8") as f:
            f.write("recall precision rlo rhi plo phi\n")
            f.write("%.4f %.4f %.4f %.4f %.4f %.4f\n" % (m["recall"], m["precision"], m["recall_ci"][0],
                                                         m["recall_ci"][1], m["precision_ci"][0], m["precision_ci"][1]))


def write_signals_table(mode, eps):
    """Which evidence kinds supported the detection of each agent or component episode."""
    rows = {}
    for e in eps:
        if e["scope"] != "main" or e["label"] == "benign" or not e["detected"]["AD"]:
            continue
        for k in e["ad_signals"]:
            rows.setdefault(k, []).append(e["id"])
    order = ["network", "behavior", "base-url", "listener", "module", "mcp-server", "browser-automation"]
    lines = [r"\begin{tabular}{@{}l l r >{\raggedright\arraybackslash}p{5.4cm}@{}}", r"\toprule",
             r"Evidence kind & Layer & Episodes & Which \\", r"\midrule"]
    layer = {"network": "L3 network", "behavior": "L2 runtime", "base-url": "L2/L5 configuration",
             "listener": "L3 network", "module": "L2 runtime", "mcp-server": "L2 runtime",
             "browser-automation": "L2 runtime", "env": "L2 runtime"}
    for k in order + sorted(set(rows) - set(order)):
        if k in rows:
            lines.append("%s & %s & %d & %s \\\\" % (tex_escape(KIND_LABELS.get(k, k)), tex_escape(layer.get(k, "other")),
                                                     len(rows[k]), ", ".join(sorted(rows[k]))))
    lines += [r"\bottomrule", r"\end{tabular}"]
    with open(os.path.join(TEX, "tab-signals-%s.tex" % mode), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def write_finding_excerpt(run_dir, episode="A02"):
    """A real finding of the evaluation, anonymised, for the appendix."""
    ep_path = os.path.join(run_dir, "episodes", episode + ".json")
    if not os.path.exists(ep_path):
        return
    ep = load_json(ep_path)
    pids = {int(p["pid"]) for p in ep["processes"]}
    for scan in ep["agent_detector"]["scans"]:
        scan_path = os.path.join(run_dir, "scans", scan)
        if not os.path.exists(scan_path):
            return  # raw scans are not published
        rep = load_json(scan_path)
        for f in rep["findings"]:
            if f["tool_id"].startswith("probable-agent") and any(e.get("pid") in pids for e in f["evidence"]):
                text = json.dumps(f, indent=2, ensure_ascii=True)
                # Anonymise the workstation: host, account, SID and profile path.
                for old, new in ((rep["host"], "HOST"), (rep["run_as"].split("\\")[-1], "user")):
                    text = text.replace(old, new)
                if f.get("user_sid"):
                    text = text.replace(f["user_sid"], "S-1-5-21-...")
                text = text.replace("\\\\Users\\\\" + rep["run_as"].split("\\")[-1], "\\\\Users\\\\user")
                # Wrap long lines so that the excerpt fits the page.
                wrapped = []
                for line in text.splitlines():
                    indent = len(line) - len(line.lstrip())
                    while len(line) > 86:
                        wrapped.append(line[:86])
                        line = " " * (indent + 4) + line[86:]
                    wrapped.append(line)
                text = "\n".join(wrapped)
                with open(os.path.join(TEX, "app-finding.tex"), "w", encoding="utf-8") as out:
                    out.write("% Generated by score.py: do not edit.\n{\\footnotesize\n\\begin{verbatim}\n")
                    out.write(text + "\n\\end{verbatim}\n}\n")
                return


def percentile(values, q):
    if not values:
        return None
    v = sorted(values)
    k = (len(v) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(v) - 1)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def score_overhead(mode):
    path = os.path.join(RESULTS, mode, "overhead.jsonl")
    if not os.path.exists(path):
        return None
    rows = [json.loads(l) for l in open(path, encoding="utf-8-sig") if l.strip()]
    out = {"runs": len(rows)}
    for key in ("duration_ms", "wall_ms", "cpu_time_ms", "peak_working_set_mb", "processes", "connections"):
        vals = [r[key] for r in rows if r.get(key) is not None]
        out[key] = {"median": statistics.median(vals) if vals else None,
                    "p95": percentile(vals, 0.95), "max": max(vals) if vals else None}
    collectors = {}
    for r in rows:
        for name, ms in (r.get("collectors_ms") or {}).items():
            collectors.setdefault(name, []).append(ms)
    collectors.setdefault("correlate", [r["correlate_ms"] for r in rows if r.get("correlate_ms") is not None])
    out["collectors"] = {n: {"median": statistics.median(v), "p95": percentile(v, 0.95)}
                         for n, v in sorted(collectors.items()) if v}
    return out


def write_overhead_cdf(mode):
    """Sorted scan durations, for the cumulative distribution figure."""
    path = os.path.join(RESULTS, mode, "overhead.jsonl")
    if not os.path.exists(path):
        return
    rows = [json.loads(l) for l in open(path, encoding="utf-8-sig") if l.strip()]
    dur = sorted(r["duration_ms"] for r in rows)
    wall = sorted(r["wall_ms"] for r in rows)
    cpu = sorted(r["cpu_time_ms"] for r in rows)
    with open(os.path.join(TEX, "overhead-%s.dat" % mode), "w", encoding="utf-8") as f:
        f.write("frac duration wall cpu\n")
        for i in range(len(dur)):
            f.write("%.3f %.1f %.1f %.1f\n" % ((i + 1) / len(dur), dur[i], wall[i], cpu[i]))


STAGE_LABELS = {"processes": "Processes", "network": "TCP table", "dns": "DNS cache", "traces": "Traces",
                "inventory": "Inventory", "environment": "Environment", "inspect": "Candidate inspection",
                "correlate": "Correlation"}


def write_overhead_stages(mode, ov):
    """Median and 95th percentile per stage, ranked by median, for the bar chart."""
    stages = sorted(((n, c["median"], c["p95"]) for n, c in ov["collectors"].items() if n in STAGE_LABELS),
                    key=lambda x: x[1])
    with open(os.path.join(TEX, "overhead-stages-%s.dat" % mode), "w", encoding="utf-8") as f:
        f.write("label median p95\n")
        for n, m, p in stages:
            f.write("{%s} %.1f %.1f\n" % (STAGE_LABELS[n], m, p))


def write_overhead_table(mode, ov):
    order = ["processes", "network", "dns", "traces", "inventory", "environment", "inspect", "correlate"]
    lines = [r"\begin{tabular}{@{}l r r@{}}", r"\toprule", r"Stage & Median (ms) & p95 (ms) \\", r"\midrule"]
    for n in order:
        if n in ov["collectors"]:
            c = ov["collectors"][n]
            lines.append("%s & %s & %s \\\\" % (tex_escape(STAGE_LABELS[n]), fmt(c["median"], 1), fmt(c["p95"], 1)))
    lines.append(r"\midrule")
    lines.append("Scan duration (elapsed) & %s & %s \\\\" % (fmt(ov["duration_ms"]["median"], 0), fmt(ov["duration_ms"]["p95"], 0)))
    lines.append("CPU time (all threads) & %s & %s \\\\" % (fmt(ov["cpu_time_ms"]["median"], 0), fmt(ov["cpu_time_ms"]["p95"], 0)))
    lines += [r"\bottomrule", r"\end{tabular}"]
    with open(os.path.join(TEX, "tab-overhead-%s.tex" % mode), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


LEVELS = ["residue", "installed", "recent", "active"]


def score_insitu(mode):
    """Compares the workstation scan with the hand-made ground truth."""
    path = os.path.join(RESULTS, mode, "insitu.json")
    gt_path = os.path.join(HERE, "ground-truth.csv")
    if not (os.path.exists(path) and os.path.exists(gt_path)):
        return None
    import csv
    rep = load_json(path)
    found = {f["tool_id"]: f for f in rep["findings"]}
    rows, ok = [], 0
    with open(gt_path, encoding="utf-8-sig") as f:
        for g in csv.DictReader(f):
            fd = found.get(g["tool_id"])
            exp = g["expected_level"]
            if exp == "absent":
                correct = fd is None
            elif fd is None:
                correct = False
            elif exp == "installed":
                # Use within the trace window cannot be verified independently:
                # installed or recent are both consistent with the evidence.
                correct = fd["level"] in ("installed", "recent")
            else:
                correct = fd["level"] == exp
            ok += correct
            rows.append(dict(tool_id=g["tool_id"], expected=exp, evidence=g["independent_evidence"],
                             level=fd["level"] if fd else "--", confidence=fd["confidence"] if fd else "--",
                             name=fd["tool_name"] if fd else g["tool_id"], correct=correct))
    extra = [f for tid, f in found.items() if tid not in {r["tool_id"] for r in rows}]
    return dict(rows=rows, correct=ok, total=len(rows), extra=[f["tool_id"] for f in extra])


def write_insitu_table(mode, ins):
    mark = {True: r"\cmark", False: r"\xmark"}
    lines = [r"\begin{tabular}{@{}>{\raggedright\arraybackslash}p{3.2cm} >{\raggedright\arraybackslash}p{5.4cm} l l c@{}}",
             r"\toprule", r"Tool & Evidence found by the inventory script & Expected & Reported & \\", r"\midrule"]
    for r in ins["rows"]:
        reported = "--" if r["level"] == "--" else "%s, %s" % (r["level"], r["confidence"])
        lines.append("%s & %s & %s & %s & %s \\\\" % (tex_escape(r["name"]), tex_escape(r["evidence"]),
                                                     tex_escape(r["expected"]), tex_escape(reported), mark[r["correct"]]))
    lines += [r"\bottomrule", r"\end{tabular}"]
    with open(os.path.join(TEX, "tab-insitu-%s.tex" % mode), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def score_dns_ttl(mode):
    """DNS cache expiry (dns-ttl.ps1): attribution against time since start."""
    path = os.path.join(RESULTS, mode, "dns-ttl.jsonl")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8-sig") as f:
        rows = [json.loads(line) for line in f if line.strip()]
    providers = []
    for r in rows:
        if r["provider"] not in providers:
            providers.append(r["provider"])
    out = {"providers": providers, "per_provider": {}}
    for prov in providers:
        pr = [r for r in rows if r["provider"] == prov]
        pers = [r for r in pr if r["phase"] == "persistent"]
        last = []
        for rep in sorted({r["repetition"] for r in pers}):
            att = [r["t"] for r in pers if r["repetition"] == rep and r["attributed"]]
            last.append(max(att) if att else 0)
        recon = [r for r in pr if r["phase"] == "reconnect" and r["connected"]]
        out["per_provider"][prov] = {
            "ttl_max": max((r["ttl"] for r in pr if r.get("ttl") is not None), default=None),
            "persistent_last_attributed": last,
            "persistent_connected": ratio(sum(r["connected"] for r in pers), len(pers)),
            "persistent_attributed": sum(1 for r in pers if r["attributed"]),
            "persistent_scans": len(pers),
            "reconnect_connected": len(recon),
            "reconnect_attributed": sum(1 for r in recon if r["attributed"]),
        }
    ts = sorted({r["t"] for r in rows if r["phase"] == "persistent"})
    with open(os.path.join(TEX, "dns-ttl-%s.dat" % mode), "w", encoding="utf-8") as f:
        f.write("t " + " ".join(providers) + "\n")
        for t in ts:
            vals = []
            for prov in providers:
                cell_rows = [r for r in rows if r["phase"] == "persistent" and r["provider"] == prov and r["t"] == t]
                vals.append(fmt(ratio(sum(r["attributed"] for r in cell_rows), len(cell_rows))))
            f.write("%d %s\n" % (t, " ".join(vals)))
    # One row per provider and repetition (persistent phase), four rows per
    # provider: ya is the row when the connection was attributed, yc when the
    # agent was connected but not attributed (nan otherwise), for a strip plot.
    reps = sorted({r["repetition"] for r in rows if r["phase"] == "persistent"})
    with open(os.path.join(TEX, "dns-ttl-strip-%s.dat" % mode), "w", encoding="utf-8") as f, \
            open(os.path.join(TEX, "dns-ttl-marks-%s.dat" % mode), "w", encoding="utf-8") as g:
        f.write("t y ya yc\n")
        g.write("y ttl\n")
        for i, prov in enumerate(providers):
            for j, rep in enumerate(reps):
                y = 4 * i + j + 1
                cells = [r for r in rows if r["phase"] == "persistent" and r["provider"] == prov
                         and r["repetition"] == rep]
                for r in sorted(cells, key=lambda r: r["t"]):
                    ya = y if r["attributed"] else "nan"
                    yc = y if r["connected"] and not r["attributed"] else "nan"
                    f.write("%d %d %s %s\n" % (r["t"], y, ya, yc))
                ttl = next((r["ttl"] for r in cells if r.get("ttl") is not None), None)
                if ttl is not None:
                    g.write("%d %d\n" % (y, ttl))
    return out


def score_intermittent(mode):
    """Intermittent agent scanned at random moments (intermittent.ps1)."""
    path = os.path.join(RESULTS, mode, "intermittent.jsonl")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8-sig") as f:
        rows = [json.loads(line) for line in f if line.strip()]
    n = len(rows)
    out = {"scans": n}
    for key in ("connected", "shell", "llm_api", "probable_agent", "actionable"):
        x = sum(1 for r in rows if r[key])
        out[key] = {"count": x, "ratio": ratio(x, n), "ci": clopper_pearson(x, n)}
    # Of the scans taken while the agent had a connection open, how many attributed it.
    conn = [r for r in rows if r["connected"]]
    out["actionable_when_connected"] = {"count": sum(1 for r in conn if r["actionable"]), "of": len(conn)}
    return out


def main():
    os.makedirs(TEX, exist_ok=True)
    macros = ["% Generated by score.py: do not edit."]
    for mode, prefix in MODE_PREFIX.items():
        runs = load_runs(mode)
        if not runs:
            continue
        eps = aggregate(runs)
        main_eps = [e for e in eps if e["scope"] == "main"]
        robust = [e for e in eps if e["scope"] == "robustness"]
        metrics = task_metrics(eps, ("agent",))
        ai_metrics = task_metrics(eps, ("agent", "component"))
        comps = [e for e in main_eps if e["label"] == "component"]
        components = {d: sum(1 for e in comps if e["detected"][d]) for d, _ in DETECTORS}
        components["total"] = len(comps)
        unstable = sorted("%s/%s" % (e["id"], d) for e in eps for d, _ in DETECTORS if 0 < e["counts"][d] < e["runs"])
        background = {d: sorted({b for e in eps for b in e["background"][d]}) for d in ("D0", "D1", "D2")}
        write_episode_table(mode, eps)
        write_metrics_table(mode, metrics, components)
        write_pr_data(mode, metrics)
        write_signals_table(mode, eps)
        if mode == "standard":
            write_finding_excerpt(runs[-1]["dir"])
        n_agents = sum(1 for e in main_eps if e["label"] == "agent")
        n_benign = sum(1 for e in main_eps if e["label"] == "benign")
        for name, value in (("agents", n_agents), ("components", len(comps)), ("benign", n_benign),
                            ("robust", len(robust)), ("runs", len(runs)), ("unstable", len(unstable))):
            macros.append(r"\newcommand{\%s}{%d}" % (macro_name(prefix, name), value))
        for det, _ in DETECTORS:
            m = metrics[det]
            for k in ("tp", "fn", "fp", "tn"):
                macros.append(r"\newcommand{\%s}{%d}" % (macro_name(prefix, det, k), m[k]))
            for k in ("precision", "recall", "f1"):
                macros.append(r"\newcommand{\%s}{%s}" % (macro_name(prefix, det, k), fmt(m[k])))
            for k in ("precision", "recall"):
                lo, hi = m[k + "_ci"]
                macros.append(r"\newcommand{\%s}{%s}" % (macro_name(prefix, det, k, "lo"), fmt(lo)))
                macros.append(r"\newcommand{\%s}{%s}" % (macro_name(prefix, det, k, "hi"), fmt(hi)))
            macros.append(r"\newcommand{\%s}{%d}" % (macro_name(prefix, det, "components"), components[det]))
            for k in ("precision", "recall", "f1"):
                macros.append(r"\newcommand{\%s}{%s}" % (macro_name(prefix, det, "ai", k), fmt(ai_metrics[det][k])))
        metas = [r["meta"] for r in runs if r["meta"].get("run_id") != "legacy"]
        if metas:
            m0 = metas[0]
            edition = {"Core": "Home", "Professional": "Pro"}.get(m0["os"]["edition"], m0["os"]["edition"])
            for name, value in (("osEdition", edition), ("osVersion", m0["os"]["display_version"]),
                                ("osBuild", m0["os"]["build"]), ("commit", m0.get("commit") or "n/a"),
                                ("binarySha", m0["binary_sha256"][:12]), ("toolVersion", m0["tool_version"]),
                                ("catalogVersion", m0["catalog_version"]),
                                ("runFirst", metas[0]["run_id"]), ("runLast", metas[-1]["run_id"])):
                macros.append(r"\newcommand{\%s}{%s}" % (macro_name(prefix, name), tex_escape(value)))
            if len({(m["binary_sha256"], m["catalog_version"], m["os"]["build"]) for m in metas}) != 1:
                raise SystemExit("the runs of %s used different binaries, catalogs or builds" % mode)
        ov = score_overhead(mode)
        if ov:
            write_overhead_table(mode, ov)
            write_overhead_cdf(mode)
            write_overhead_stages(mode, ov)
            for key, digits in (("duration_ms", 0), ("wall_ms", 0), ("cpu_time_ms", 0), ("peak_working_set_mb", 1),
                                ("processes", 0), ("connections", 0)):
                for stat in ("median", "p95", "max"):
                    macros.append(r"\newcommand{\%s}{%s}" % (macro_name(prefix, key.replace("_", ""), stat),
                                                             fmt(ov[key][stat], digits)))
            macros.append(r"\newcommand{\%s}{%d}" % (macro_name(prefix, "overheadRuns"), ov["runs"]))
        ins = score_insitu(mode)
        if ins:
            write_insitu_table(mode, ins)
            macros.append(r"\newcommand{\%s}{%d}" % (macro_name(prefix, "insituCorrect"), ins["correct"]))
            macros.append(r"\newcommand{\%s}{%d}" % (macro_name(prefix, "insituTotal"), ins["total"]))
        ttl = score_dns_ttl(mode)
        if ttl:
            for prov, p in ttl["per_provider"].items():
                last = sorted(p["persistent_last_attributed"])
                for name, value in (("ttl", p["ttl_max"]), ("ttlLast", last[len(last) // 2] if last else None),
                                    ("ttlLastMax", last[-1] if last else None),
                                    ("ttlReconnect", p["reconnect_attributed"]),
                                    ("ttlReconnectOf", p["reconnect_connected"]),
                                    ("ttlAttributed", p["persistent_attributed"]),
                                    ("ttlScans", p["persistent_scans"])):
                    macros.append(r"\newcommand{\%s}{%s}" % (macro_name(prefix, name, prov),
                                                             "n/a" if value is None else value))
            pp = ttl["per_provider"].values()
            lasts = [t for p in pp for t in p["persistent_last_attributed"]]
            for name, value in (("ttlLastOverall", max(lasts) if lasts else 0),
                                ("ttlAttributedAll", sum(p["persistent_attributed"] for p in pp)),
                                ("ttlScansAll", sum(p["persistent_scans"] for p in pp)),
                                ("ttlReconnectAll", sum(p["reconnect_attributed"] for p in pp)),
                                ("ttlReconnectOfAll", sum(p["reconnect_connected"] for p in pp))):
                macros.append(r"\newcommand{\%s}{%d}" % (macro_name(prefix, name), value))
        inter = score_intermittent(mode)
        if inter:
            macros.append(r"\newcommand{\%s}{%d}" % (macro_name(prefix, "intScans"), inter["scans"]))
            for key in ("connected", "shell", "llm_api", "probable_agent", "actionable"):
                name = key.replace("_", "")
                v = inter[key]
                lo, hi = v["ci"]
                macros.append(r"\newcommand{\%s}{%d}" % (macro_name(prefix, "int", name), v["count"]))
                macros.append(r"\newcommand{\%s}{%s}" % (macro_name(prefix, "int", name, "ratio"), fmt(v["ratio"])))
                macros.append(r"\newcommand{\%s}{%s}" % (macro_name(prefix, "int", name, "lo"), fmt(lo)))
                macros.append(r"\newcommand{\%s}{%s}" % (macro_name(prefix, "int", name, "hi"), fmt(hi)))
            w = inter["actionable_when_connected"]
            macros.append(r"\newcommand{\%s}{%d}" % (macro_name(prefix, "intActionableConnected"), w["count"]))
            macros.append(r"\newcommand{\%s}{%d}" % (macro_name(prefix, "intConnectedOf"), w["of"]))
        summary = {
            "mode": mode, "runs": [r["meta"] for r in runs], "episodes": len(eps), "main_agents": n_agents,
            "main_components": len(comps), "main_benign": n_benign, "insitu": ins, "dns_ttl": ttl,
            "intermittent": inter,
            "metrics_agents": metrics, "metrics_ai_software": ai_metrics, "components_detected": components,
            "unstable_cells": unstable, "background_flags": background, "overhead": ov,
            "episodes_detail": [{"id": e["id"], "label": e["label"], "scope": e["scope"], "runs": e["runs"],
                                 "detections": e["counts"], "majority": e["detected"],
                                 "ad_findings": e["ad_labels"], "ad_signals": e["ad_signals"]} for e in eps],
        }
        with open(os.path.join(SUMMARIES, "summary-%s.json" % mode), "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print("%s: %d episodes, %d run(s), %d unstable cell(s)" % (mode, len(eps), len(runs), len(unstable)))
    with open(os.path.join(TEX, "macros.tex"), "w", encoding="utf-8") as f:
        f.write("\n".join(macros) + "\n")


def check():
    """Re-scores the published runs into a temporary folder and compares."""
    import re
    import tempfile
    global TEX, SUMMARIES
    published = TEX
    TEX = SUMMARIES = tempfile.mkdtemp(prefix="score-check-")
    main()

    def lines(path):
        with open(path, encoding="utf-8-sig") as f:
            return f.read().splitlines()

    rx = re.compile(r"\\newcommand\{\\(\w+)\}\{(.*)\}$")
    pub = dict(m.groups() for m in map(rx.match, lines(os.path.join(published, "macros.tex"))) if m)
    new = dict(m.groups() for m in map(rx.match, lines(os.path.join(TEX, "macros.tex"))) if m)
    differ = sorted(k for k in new if pub.get(k) != new[k])
    files = sorted(n for n in os.listdir(TEX) if n != "macros.tex" and not n.startswith("summary-"))
    files_differ = [n for n in files if not os.path.exists(os.path.join(published, n))
                    or lines(os.path.join(published, n)) != lines(os.path.join(TEX, n))]
    kept = sorted(set(os.listdir(published)) - set(os.listdir(TEX)))
    print()
    print("values (macros):  %d recomputed, %d identical to the paper" % (len(new), len(new) - len(differ)))
    print("tables and data:  %d recomputed, %d identical to the paper" % (len(files), len(files) - len(files_differ)))
    for k in differ:
        print("  DIFFERENT value  %s: paper %s, recomputed %s" % (k, pub.get(k, "(absent)"), new[k]))
    for n in files_differ:
        print("  DIFFERENT file   %s" % n)
    not_recomputed = sorted(k for k in pub if k not in new)
    if not_recomputed or kept:
        print("not recomputed here (they need the private in-situ report or raw scans, or come")
        print("from catalogdump and model.py): %s" % ", ".join(kept + not_recomputed))
    print("recomputed files: %s" % TEX)
    return 1 if differ or files_differ else 0


if __name__ == "__main__":
    if "--check" in sys.argv[1:]:
        sys.exit(check())
    main()
