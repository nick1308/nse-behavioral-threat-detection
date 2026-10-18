# Requirement Analysis

Real-Time Behavioral Threat Detection for Trading Systems — IDP
Team: Ankit V, Tusya S, Vishal Basker · Guide: Dr. Karmel A

This document exists to state, precisely and with justification, what the system must do
(functional requirements) and how well it must do it (non-functional requirements). Every
numeric target below is either traced to a specific source or explicitly marked as an
engineering choice with its own stated rationale — nothing is asserted without saying why.

---

## 1. Functional Requirements

| ID | Requirement |
|---|---|
| FR-1 | The system shall ingest a stream of simulated trading events (LOGIN, ORDER, CANCEL_ORDER, API_REQUEST, etc. — see `EVENT_SCHEMA.md`) via a pluggable `EventSource` interface. |
| FR-2 | The system shall maintain a rolling per-account behavioral baseline (e.g. mean/std of order size, actions-per-hour) computed incrementally as events arrive. |
| FR-3 | The system shall compute a statistical anomaly score (z-score deviation from the account's own baseline) for each incoming event as an interpretable first layer. |
| FR-4 | The system shall evaluate an event using account behavior and produce an explainable risk assessment. The current backend uses rolling z-score signals and an Isolation Forest signal. |
| FR-5 | The system shall combine active risk signals into one alert score, give the operator a human-readable explanation, and retain the component scores for diagnostics. The score is not a calibrated probability. |
| FR-6 | The system shall provide a browser-based analyst interface that submits or replays events through the API and displays current risk, reasons, event details, and recent alert history. |
| FR-7 | The system shall detect three concrete attack patterns: account takeover, API abuse, and automated trading (signal definitions in `DECISIONS.md` §8). |
| FR-8 | The system shall be evaluated against a synthetic, ground-truth-labeled dataset (`is_attack`, `attack_type` fields, never exposed to the detection pipeline itself). |

## 2. Non-Functional Requirements — with justification

### NFR-1: Recall (detection rate) ≥ 80% on our labeled synthetic dataset

**Status: working target, not a literature guarantee.** Isolation Forest's reported recall
varies enormously by dataset — from as low as 2–17% on adversarial/network-traffic synthetic
data [3] to 91% precision/recall/accuracy on the CERT insider-threat dataset [2], which is the
closest published analogue to our behavioral, account-level, moderately-imbalanced setting.
80% is chosen as a target *within* that plausible range for a CERT-like setup, not as a number
we can cite a single paper guaranteeing. **We commit to reporting our actual measured recall,
whatever it turns out to be, rather than defending 80% as fixed** — this is stated directly in
`DECISIONS.md` §1 as a "working number, revise after baselining."

### NFR-2: False positive rate < 10%

**Status: engineering requirement, not a literature-derived number.** None of the papers
reviewed (see References) report FPR as an isolated metric for Isolation Forest — it is
usually only inferable from (1 − precision), and precision itself ranges from single digits
[3] to 91% [2] depending on dataset. We set <10% FPR as our own requirement because it is the
threshold above which a human analyst cannot realistically triage the alert volume — this is
an interpretable-workload constraint, not a benchmark we are matching.

### NFR-3: Detection latency < 5 seconds

**Status: deliberately different from production fintech, for a stated reason.** Production
card-network fraud scoring targets 10–50ms end-to-end because it gates a live transaction
authorization within a ~100ms budget [4]. Our system does **not** gate or block a trade — it
raises an alert to a human analyst asynchronously. The relevant bar is therefore "fast enough
to feel real-time on a live dashboard," not "fast enough to authorize a transaction." 5 seconds
is chosen as a human-perceptible real-time threshold for an alerting (not blocking) workflow,
consistent with our own architecture, not derived from fintech authorization latency numbers.
We state this distinction explicitly so it isn't mistaken for a claim of production-grade
low-latency fraud gating, which this project does not attempt.

### NFR-4: No labeled fraud data required for the core ML layer

Directly justified by Isolation Forest's design — trained on (mostly) normal behavior,
requires no labeled anomalies [1]. This is a property of the algorithm, not a target we chose.

### NFR-5: Modular monolith, extract services only where load-tested

Engineering principle stated in `DECISIONS.md` §7 — no number to justify, but stated here for
completeness since it constrains architecture (see `DESIGN.md`).

---

## 3. Current evidence and gaps (checked 2026-10-18)

- Fixed-seed z-score, Isolation Forest, and combined measurements are recorded
  in [`EVALUATION_BASELINE.md`](EVALUATION_BASELINE.md). The combined fixed-seed
  result is 90.7% event recall and 3.0% FPR; it measures planted generator
  patterns, not independent real or unseen trading behavior.
- The 80% recall and <10% FPR targets remain working numbers, not guarantees. Report the actual
  measurements and revise the targets only after broader baselining and independent evaluation.
- The Forest is included in `/score` through the max-score ensemble, as well as
  evaluated separately. On the recorded seed-42 run, standalone Forest event
  recall was 3.5% and FPR was 5.2%; it missed API-abuse and automated-trading
  scenarios. The ensemble improves event recall to 90.7% while increasing FPR
  from 0.0% to 3.0% versus z-score alone.
- The five-seed check changes generator profile choices, not planted attack
  mechanisms. It is a stability check, not held-out generalization evidence.
  Reported latency excludes API and network costs.
- A local dashboard and synthetic event replay now exist. There is no live
  broker integration or persistent event store; dashboard history is in memory.
  WebSocket feed and graph-based detection remain unimplemented.
  `EVENT_SCHEMA.md` defines the normalized API event contract and notes which
  event types currently remain ungenerated by the synthetic source.
  types not yet generated or supported by the scoring API.
- Isolation Forest's own literature performance is dataset-dependent enough that we cannot
  promise 80% recall with confidence yet; our defensible claim is the target's *reasoning*
  (why 80% is a sane starting point given CERT-like precedent), not a guarantee.

---

## References

1. Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). Isolation Forest. *ICDM'08*, 413–422.
2. Insider Threat Detection Using Machine Learning Approach. *Applied Sciences*, 13(1), 259 (2023). MDPI. Isolation Forest: 91% accuracy/precision/recall/F1 on CERT-derived data. https://www.mdpi.com/2076-3417/13/1/259
3. Evaluating the Isolation Forest Method for Anomaly Detection (synthetic network-traffic data; precision/recall as low as 0.007/0.02 to 0.07/0.18 across simulations, illustrating dataset-dependence). https://journal.esrgroups.org/jes/article/download/639/661/1089
4. Real-Time Fraud Detection: Latency, Features & Scale — Redis Inc. engineering blog; 10–50ms fraud-scoring window within a ~100ms card-authorization budget. https://redis.io/blog/real-time-fraud-detection/
5. SilIF: Silhouette-Augmented Isolation Forest for Unsupervised Transaction Fraud Detection (IEEE-CIS dataset; plain Isolation Forest AUC-ROC 0.722, AUC-PR 0.126 — cited to show IF performance is dataset-dependent, not to justify our targets). https://arxiv.org/html/2605.26135v1
