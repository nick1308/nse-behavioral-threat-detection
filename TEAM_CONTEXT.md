# Project Context for Team Members

**Read this first.** This file exists so any team member — or their own Claude session —
can get oriented on this project in one read: what we're building, why we made the
choices we made, exactly what's done, and what's still needed before Review 2 (Sep
21–25, 2026) and beyond.

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

**Not** a price-prediction or market-manipulation tool — see `docs/LITERATURE_SURVEY.md`
for exactly how this differs from existing market-surveillance research (that field
studies price/order-book patterns; we study individual account behavior).

## Why the key decisions were made — read `DECISIONS.md` for full detail, summary here

- **Two-layer detection**: a rolling per-account statistical baseline (z-score, done) as
  an interpretable floor, plus Isolation Forest (not yet built) as the ML layer.
  Statistical layer first because it needs no training data and every result can be
  sanity-checked by hand.
- **Synthetic, ground-truth-labeled data**, not scraped real market data — legally
  necessary (no NSE ToS violation) and methodologically necessary (no labeled fraud
  ground truth exists in real data; this is standard practice, e.g. the CERT
  insider-threat dataset is also fully synthetic for the same reason).
- **Modular monolith**, not microservices — no premature infrastructure; each layer
  (ingestion/features/detection/api) is a separate Python package behind an abstract
  interface so it can be swapped or extracted later without a rewrite.
- **No UI/dashboard yet, and that's correct, not a gap** — confirmed directly against
  the official rubric (`docs/REVIEW_SCHEDULE.md`): Review 2 is graded on requirement
  analysis, system design, component selection, and prototype feasibility. The
  dashboard becomes rubric-relevant starting Review-IV (Jan 2027) and is expected by
  Review-V (Mar 2027) — building it now would be effort spent before it's needed.

## Where the numbers come from — every threshold is either cited or flagged as ours

`docs/REQUIREMENTS.md` states every target (80% recall, <10% false-positive rate, <5s
latency) with either a literature citation or an explicit "this is our own engineering
choice, here's why" — **none of these are guaranteed outcomes**, they're working targets
we've committed to revising once we have real measured numbers. If a guide asks "why
80%?", the honest answer is in that doc — don't claim more certainty than we have.

## What's actually built right now (as of 2026-09-19, commit `a585ede` on `main`)

| Component | Status | File(s) |
|---|---|---|
| Requirement analysis | Done | `docs/REQUIREMENTS.md` |
| System design + architecture diagram | Done | `docs/DESIGN.md` |
| Literature survey + research gap | Done | `docs/LITERATURE_SURVEY.md` |
| Synthetic event generator (3 attack types, ground-truth labeled) | Done, 14 tests | `src/threat_detection/ingestion/synthetic.py` |
| Statistical feature extraction (rolling per-account stats) | Done, 9 tests | `src/threat_detection/features/rolling_stats.py` |
| Z-score anomaly detector (explainable 0-100 risk score) | Done, 9 tests | `src/threat_detection/detection/zscore.py` |
| `POST /score` API endpoint (full pipeline wired end-to-end) | Done, 5 tests | `src/threat_detection/api/main.py` |
| **Total: 37 passing tests**, `pytest` from repo root | | |

Run it yourself: `uvicorn threat_detection.api.main:app --app-dir src --reload`, then
POST an event (shape in `EVENT_SCHEMA.md`) to `http://localhost:8000/score`, or use the
interactive docs at `http://localhost:8000/docs`.

## What's NOT built yet — this is where team contribution is most needed

1. **Isolation Forest detector** (`src/threat_detection/detection/` — interface exists
   in `base.py`, no concrete implementation yet). This is explicitly future scope per
   `DESIGN.md`, planned for after Review 2, but someone should start reading up on
   scikit-learn's `IsolationForest` now.
2. **The actual Review-2 PPT** (8 mandatory slides, see `docs/REVIEW_SCHEDULE.md` for
   exact structure/rubric). Content exists in `docs/LITERATURE_SURVEY.md`,
   `docs/DESIGN.md`, `DECISIONS.md` — needs assembling into slides, and **guide approval
   is mandatory before the review**, so get this in front of Dr. Karmel A early.
3. **Autoencoder comparison method** (DECISIONS.md §5) — future scope, not urgent.
4. **PostgreSQL/Redis persistence** — everything today is in-memory only, intentional
   for a single-process prototype (DESIGN.md §3), will matter once the system needs to
   survive a restart or run multi-process.
5. **React dashboard + WebSocket live feed** — deliberately deferred to the Review-IV/V
   window (Jan–Mar 2027), not before.
6. **Evaluation harness**: run the synthetic generator's ground-truth-labeled events
   through the detector, compute actual precision/recall/FP-rate, compare against the
   working targets in `docs/REQUIREMENTS.md`. This is what turns "80% recall" from a
   target into a real, defensible measured number — high-value next step once Isolation
   Forest exists to compare against the statistical baseline.

## Repo map

```
docs/REQUIREMENTS.md       -- functional/non-functional requirements, cited
docs/DESIGN.md              -- architecture diagram, data flow, scoping
docs/LITERATURE_SURVEY.md   -- research gap, for PPT slides 3-5
docs/REVIEW_SCHEDULE.md     -- full program rubric + Review-2 PPT structure
DECISIONS.md                 -- why every technical choice was made, with citations
EVENT_SCHEMA.md               -- the event contract every layer is built against
src/threat_detection/
  ingestion/synthetic.py    -- generates events + plants attacks
  features/rolling_stats.py -- turns events into behavioral feature vectors
  detection/zscore.py       -- scores features, explains the score
  api/main.py                -- POST /score wires it all together
tests/                        -- one test dir per layer, 37 tests total
```

## Ground rules if you're picking up work here

- **Don't let the detection pipeline see `is_attack`/`attack_type`** — those fields
  exist only for evaluation, and a detector that reads them is solving a fake, trivial
  problem. See the module docstring in `synthetic.py`.
- **Every new dependency needs sign-off first** — don't `pip install` something new
  without checking with the team (this was Ankit's explicit rule from day one).
- **Run `pytest` before committing** — 37 tests currently pass; don't merge something
  that breaks them.
- **Cite real numbers, don't invent them** — if you add a new threshold or claim
  (recall, latency, whatever), either find a source or mark it explicitly as "our own
  engineering choice, here's why," matching the pattern in `docs/REQUIREMENTS.md`.
