# Project Context for Team Members

**Read this first.** This file orients team members and AI coding tools on the project,
its decisions, verified implementation status, and current gaps. Status last checked
on 2026-10-18; verify the checkout before repeating test or performance claims.

If you're pasting this into your own Claude/ChatGPT session to get help, paste this
whole file first and say "this is context for a project I'm contributing to."

---

## What this project is

A real-time behavioral threat detection platform for a simulated Indian retail trading
system — flags account takeover, API abuse, and automated trading by learning each
account's own normal behavior and scoring deviation from it, with an explainable 0–100
risk score (not a black-box "fraud/not fraud" label). IDP college project, Aug 2026 –
Feb/Mar 2027 (~7 months), team of 3: Ankit V, Tusya S, Vishal Basker, guided by Dr.
Karmel A.

**Not** a price-prediction or market-manipulation tool. A standalone literature-survey
file is not present in this checkout; related references and rationale are recorded in
`DECISIONS.md` and `docs/REQUIREMENTS.md` and should be consolidated before claiming a
completed survey.

## Why the key decisions were made — read `DECISIONS.md` for full detail, summary here

- **Two-layer detection**: a rolling per-account statistical baseline (z-score, built)
  as an interpretable floor, plus an Isolation Forest comparison fit on normal-only
  synthetic histories. `/score` combines layers by maximum score and includes both
  layer scores. The Forest produces a binary anomaly signal mapped only to the 50-point
  review floor, not to high severity; the z-score layer supplies stronger risk scores
  and the attack-type guess.
- **Synthetic, ground-truth-labeled data**, not scraped real market data — legally
  necessary (no NSE ToS violation) and methodologically necessary (no labeled fraud
  ground truth exists in real data; this is standard practice, e.g. the CERT
  insider-threat dataset is also fully synthetic for the same reason).
- **Modular monolith**, not microservices — no premature infrastructure; each layer
  (ingestion/features/detection/api) is a separate Python package behind an abstract
  interface so it can be swapped or extracted later without a rewrite.
- **A local analyst dashboard is implemented for the synthetic demo.** Broker-specific
  integration and persistent event storage are not implemented.

## Where the numbers come from — every threshold is either cited or flagged as ours

`docs/REQUIREMENTS.md` states every target (80% recall, <10% false-positive rate, <5s
latency) with either a literature citation or an explicit "this is our own engineering
choice, here's why" — **none of these are guaranteed outcomes**, they're working targets
we've committed to revising once we have real measured numbers. If a guide asks "why
80%?", the honest answer is in that doc — don't claim more certainty than we have.

## Verified implementation status (2026-10-18)

| Component | Status | File(s) |
|---|---|---|
| Requirement analysis | Done | `docs/REQUIREMENTS.md` |
| System design + architecture diagram | Done | `docs/DESIGN.md` |
| Literature references and rationale | Partial; no standalone survey document | `DECISIONS.md`, `docs/REQUIREMENTS.md` |
| Synthetic event generator (3 attack types, labeled, fixed-seed reproducible with fixed start time) | Implemented | `src/threat_detection/ingestion/synthetic.py` |
| Canonical event model and broker mapping | Reusable model and flat-field adapter implemented; no broker-specific config or connection | `src/threat_detection/ingestion/schema.py`, `src/threat_detection/ingestion/base.py` |
| Rolling features (quantity/value, device/login context, per-client API rate, matched cancel sequence, market-time context) | Implemented | `src/threat_detection/features/rolling_stats.py` |
| Explainable z-score detector (risk score and attack-pattern guess) | Implemented | `src/threat_detection/detection/zscore.py` |
| FastAPI `/health`, `/score`, event history, synthetic replay, dashboard | Implemented for local demo; no broker integration | `src/threat_detection/api/main.py`, `src/threat_detection/api/static/` |
| Synthetic evaluation harness | Implemented; scenario and event metrics recorded | `src/threat_detection/evaluation/`, `docs/EVALUATION_BASELINE.md` |
| Isolation Forest and score combiner | Implemented in evaluation and `/score`; fixed-seed normal-only fit and calibration streams | `src/threat_detection/detection/`, `src/threat_detection/api/main.py` |
| **Test suite** | **78 passed, 1 dependency deprecation warning** | Verified 2026-10-18 with `.venv\Scripts\python.exe -m pytest -q` |

Run it yourself: `uvicorn threat_detection.api.main:app --app-dir src --reload`, then
POST an event (shape in `EVENT_SCHEMA.md`) to `http://localhost:8000/score`, use the
interactive docs at `http://localhost:8000/docs`, or open the analyst dashboard at
`http://localhost:8000/` and select **Run demo stream**.

## Current gaps and next work

1. **Broader evaluation.** The fixed-seed combined run detects 4/4 synthetic scenarios,
   with 90.7% event recall and 3.0% FPR. Across five generator seeds, mean FPR is 3.4%
   and event recall is 90.7%. This is not an independent estimate; hold out attack patterns
   before making broader claims.
2. **API end-to-end evaluation.** Current reported latency measures feature extraction plus
   detector scoring, not request validation, transport, or process startup/model fitting.
3. **Model lifecycle.** The API fits a demo model from fixed normal-only synthetic histories
   at module import; persistence, retraining, and loading a real account population remain open.
4. **Analyst dashboard workflow.** A first local UI replays events and shows reasons and
   history; review it in a browser and improve the detail and accessibility based on use.
5. **Persistence and broker adapter.** The normalized contract and abstract mapping
   interface exist, but no broker-specific mapping is implemented. Choose a broker
   schema, then determine restart/history behavior and add persistence.

## Repo map

```
docs/REQUIREMENTS.md       -- functional/non-functional requirements, cited
docs/DESIGN.md              -- architecture diagram, data flow, scoping
DECISIONS.md                 -- why every technical choice was made, with citations
EVENT_SCHEMA.md               -- the event contract every layer is built against
src/threat_detection/
  ingestion/synthetic.py    -- generates events + plants attacks
  ingestion/schema.py       -- canonical broker-neutral event contract
  ingestion/base.py         -- source and broker-adapter extension points
  features/rolling_stats.py -- turns events into behavioral feature vectors
  detection/zscore.py       -- scores features, explains the score
  evaluation/                -- ground-truth-safe replay and baseline report
  api/main.py                -- /health and /score wire the pipeline
tests/                        -- focused tests per layer and evaluation scenario
```

See `PROGRESS.md` for the product-oriented finish plan and alternatives. Detector metrics
are supporting validation, not the project's purpose. The historical materials in
`Claude outputs/` are Review II snapshots and are not current implementation evidence.

## Ground rules if you're picking up work here

- **Don't let the detection pipeline see `is_attack`/`attack_type`** — those fields
  exist only for evaluation, and a detector that reads them is solving a fake, trivial
  problem. See the module docstring in `synthetic.py`.
- **Every new dependency needs sign-off first** — scikit-learn was approved for the current
  Isolation Forest comparison.
- **Run `pytest` before committing** — 78 tests passed on 2026-10-18; don't merge something
  that breaks them.
- **Cite real numbers, don't invent them** — if you add a new threshold or claim
  (recall, latency, whatever), either find a source or mark it explicitly as "our own
  engineering choice, here's why," matching the pattern in `docs/REQUIREMENTS.md`.
