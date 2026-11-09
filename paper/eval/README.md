# Evaluation bench

This folder holds the evaluation bench of the paper *Detecting Shadow AI:
Unsanctioned LLM Agents on Enterprise Endpoints. A Taxonomy, an Open Detector
and a Controlled Evaluation* (Jeremy Canale and Fabien Soulis), and the
results it produced for Agent Detector 0.3.2 with catalog 2026.11.09.

The bench compares Agent Detector with a signature detector and two
behavioural rules on synthetic agents, AI components, behavioural twins (the
same programs talking to non-AI services) and ordinary developer workloads.
It uses no account and no API key: the synthetic agents poll real LLM
endpoints with an invalid key and receive HTTP 401, so no prompt or data is
sent and nothing is billed.

## Requirements

Windows 10 or 11 with Python 3, Node.js, Go, .NET, Git and Chrome. Episode R03
needs the Ubuntu distribution of WSL 2; the relay episodes use `httpbin.org`
as a stand-in relay.

Build the detector first, from the repository root:

```powershell
.\build.ps1 -Version 0.3.2      # writes dist\detectoragent.exe, used by the bench
```

## Run

```powershell
cd paper\eval
Set-ExecutionPolicy -Scope Process Bypass
.\run-all.ps1        # five runs of the episodes and the other experiments, about 100 minutes
```

Started from a standard PowerShell window, it measures the standard-user
configuration (`results\standard`). Started from an administrator window, it
measures the configuration closest to the production SYSTEM task, with BAM,
Prefetch and the processes of other users readable (`results\admin`). The
bench refuses to start while processes of an interrupted run are still alive.
Close other heavy applications first.

The DNS cache expiry experiment runs separately, alone on the machine and at
least five minutes after any other part of the bench, because a recent
resolution of the same host names would refresh the cache entries it
measures:

```powershell
.\dns-ttl.ps1        # about 30 minutes
python score.py
```

`score.py` scores every run and writes the tables, data files and LaTeX
macros of the paper to `results\tex`; `go run ./paper/eval/catalogdump`, from
the repository root, writes the appendix tables of the catalog.

## Files

| File | Role |
|---|---|
| `agents/` | Synthetic agents in Python, Node.js and PowerShell |
| `workloads/dev-loop.ps1` | Benign developer workloads |
| `lib.ps1` | Helpers and the three baseline detectors |
| `run-episodes.ps1` | Episodes, baselines and Agent Detector scans |
| `bench-overhead.ps1` | Cost of 100 consecutive scans |
| `intermittent.ps1` | Intermittent agent scanned at random moments |
| `dns-ttl.ps1` | Attribution through the DNS cache as entries expire |
| `insitu.ps1`, `inventory.ps1`, `ground-truth.csv` | In-situ cross-check on the workstation |
| `score.py` | Scoring, tables and macros |
| `model.py` | Illustrative growth model of the paper |
| `catalogdump/` | Appendix tables from the catalog |
| `run-all.ps1` | Runs everything for the current privilege level |

## Published results

`results\standard` and `results\admin` hold the runs of version 0.3.2;
`results\archive-v0.3.0` and `results\archive-v0.3.1` hold the runs of the
earlier versions that the paper discusses. Each run records its provenance
(Windows build, commit, SHA-256 of the executable, catalog version), and
`score.py` refuses to combine runs that differ in any of them.

The raw scan reports, the in-situ report and the inventory identify the
workstation (host and user names, paths) and are not published; the tables
and numbers derived from them are.
