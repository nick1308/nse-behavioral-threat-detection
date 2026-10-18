# Project status and finish plan

Status checked: 2026-10-18. This is the living product-status page. Files in
`Claude outputs/` are historical Review II snapshots, not current product evidence.

## Progress at a glance

Planning estimate for delivery of the intended software product (not an official
IDP mark or measured quality score): **about 60%**. The backend and a first
working dashboard flow now exist; broker integration, durable operation, and
stronger validation remain.

| Workstream | Progress | Current state |
|---|---:|---|
| Detection backend | `████████░░` 80% | Scoring pipeline and tests exist; Isolation Forest contribution and model lifecycle need more validation |
| Analyst UI | `████████░░` 80% | Dashboard, risk reasons, filters, event history, and seeded replay work; visual/user review remains |
| End-to-end product workflow | `███████░░░` 70% | UI calls FastAPI replay/history; durable storage and broker adapter are absent |
| Reliability and validation | `██████░░░░` 60% | 77 tests pass; held-out attack variants and deployment checks remain |
| Report/demo readiness | `███░░░░░░░` 30% | Status docs refreshed; guided live walkthrough and final report materials remain |

The overall estimate is a rough product-readiness estimate weighted toward
working end-to-end functionality. The local synthetic demo now has an analyst
view. It is not connected to a broker, and synthetic planted-signature results
are not general validation.

## What exists now

- A Python backend with abstract `EventSource`, `FeatureExtractor`, and
  `AnomalyDetector` contracts and concrete synthetic source, rolling feature
  extractor, z-score detector, Isolation Forest, and max-score ensemble.
- FastAPI `/health` and `/score`; `/score` rejects evaluation labels and returns
  an explainable risk score, layer scores, and a z-score pattern guess.
- A synthetic replay/evaluation harness and automated tests. Latest test run:
  77 passed with one Starlette deprecation warning. Fixed-seed measurements and
  caveats are in `docs/EVALUATION_BASELINE.md`.
- Docker packaging files exist, but a Docker image build has not been verified
  because the local Docker engine was unavailable during the last attempt.
- A local analyst dashboard is served by FastAPI. It replays a fixed-seed,
  fixed-start-time synthetic stream, shows recent event risk, explanations,
  detector component scores, suspected pattern guesses, and risk filters.
  State/history are in memory only.
- Live local smoke check: health, dashboard, CSS, and JavaScript returned 200;
  two seed-42 runs each scored 283 synthetic events, produced 87 alerts, and
  returned identical event histories with no ground-truth fields exposed.
  These counts describe the demo replay, not detector generalization.
- `NormalizedEvent` in `ingestion/schema.py` is the canonical broker-neutral
  event contract used by the API. `ConfiguredFieldMapAdapter` maps flat source
  field names and event-type aliases into it; `BrokerEventAdapter.normalize()`
  remains the extension point for custom transformations. No broker-specific
  configuration or live broker connection exists. Device and IP telemetry may be absent; the feature
  extractor treats missing values as unavailable and does not add missing order
  quantities or values to the behavioral baseline.

## Product finish plan

1. **Complete the broker event boundary.** The canonical normalized event model,
   adapter contract, and reusable flat-field mapping adapter exist. Configure
   and validate a broker mapping only after choosing a provider and receiving
   its authorized event schema. The demo uses `SyntheticEventSource`; no live
   integration is claimed.
2. **Refine the risk assessment.** Keep explanations tied to observable signals,
   validate threshold behavior and known limitations, and improve the weak
   standalone Forest contribution before treating it as production-ready.
3. **Review the analyst experience.** Exercise the dashboard with normal and
   attack examples, tune usability/accessibility, and verify alert detail and
   filter behavior in a browser.
4. **Make the workflow reliable.** Specify startup, model initialization,
   state reset/restart behavior, validation, loading/error/empty states, and
   test the complete UI-to-score path.
5. **Validate product behavior.** Verify representative normal and attack
   scenarios, review false alarms, and add held-out attack variations. Detector
   metrics support product decisions; algorithm comparison is not the project
   goal.
6. **Package and demonstrate.** Verify a clean local setup and Docker build,
   document the run steps, prepare a scripted UI walkthrough, and refresh the
   report/review materials using verified product behavior. Preserve old review
   slides as history.

## Frontend options

- **Current choice:** a small browser UI served by the existing FastAPI app
  using HTML, CSS, and JavaScript. It avoids a second build toolchain and is
  easy to run in a local demo.
- **React + Vite:** suitable for a richer multi-page analyst product, with the
  tradeoff of separate frontend tooling and build steps.
- **Streamlit:** quickest dashboard prototype, with less control over a
  conventional product UI and client/API separation.

Regardless of framework, the acceptance outcome is: an operator can run the
app, generate or submit events, see risks and reasons, and inspect event history
without Swagger or a terminal.

## Detection design alternatives

- **Explainable scenario signals as primary risk logic:** use new-device/login
  context, unusual orders, request bursts, and repeated order-cancel timing;
  use rolling statistics to establish the user's baseline. This maps directly
  to the displayed reasons and threat scenarios, but must be tested against
  attack variations so it does not merely memorize the generator.
- **Current statistical plus Isolation Forest signals:** retain both inputs
  behind one risk result. The current Forest has weak standalone recall in the
  synthetic baseline; it should not drive the UI as a separate model contest.
- **Supervised classifier on synthetic labels:** possible as an upper-bound
  experiment, but likely to learn generator rules and weakens the unsupervised
  premise. It should not be the default product approach.
- **LOF, One-Class SVM, or autoencoder:** defer unless evidence shows the
  current product detector misses important behaviors. Each adds tuning,
  training, and explainability work; an algorithm change alone does not prove
  the model will generalize to broker behavior.

## Abstract contracts versus concrete implementations

`ingestion/base.py`, `features/base.py`, and `detection/base.py` define
abstract extension points including `BrokerEventAdapter`. Concrete implementations are `ConfiguredFieldMapAdapter`, `SyntheticEventSource`,
`RollingStatsFeatureExtractor`, `ZScoreAnomalyDetector`,
`IsolationForestAnomalyDetector`, and `ZScoreIsolationForestEnsemble`. The
analyst dashboard and synthetic event history/replay are implemented. A
broker-specific adapter, live exchange/broker feed, durable event storage,
Kafka, WebSocket feed, and graph detector are not implemented.
