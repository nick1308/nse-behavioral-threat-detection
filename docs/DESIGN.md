# System Design

Real-Time Behavioral Threat Detection for Trading Systems — IDP (status 2026-10-18)

Rationale for every component choice below is in `DECISIONS.md`; this document is the
architecture and data-flow view, cross-referenced back to those decisions.

## 1. Architecture diagram

```
                    ┌──────────────────────────────────────────────┐
                    │           Simulated Trading Platform          │
                    │   (synthetic event generator)                 │
                    └───────────────────────┬────────────────────────┘
                                             │ raw events (EVENT_SCHEMA.md)
                                             ▼
                    ┌──────────────────────────────────────────────┐
                    │  INGESTION  (threat_detection.ingestion)       │
                    │  EventSource interface → concrete generator    │
                    └───────────────────────┬────────────────────────┘
                                             │ dict[str, Any] event
                                             ▼
                    ┌──────────────────────────────────────────────┐
                    │  FEATURES  (threat_detection.features)         │
                    │  FeatureExtractor → rolling per-account stats  │
                    │  (mean/std of order size, actions/hour, ...)   │
                    └───────────────────────┬────────────────────────┘
                                             │ dict[str, float] feature vector
                                             ▼
                    ┌──────────────────────────────────────────────┐
                    │  DETECTION  (threat_detection.detection)       │
                    │  Layer 1: rolling z-score (interpretable floor)│
                    │  Layer 2: Isolation Forest (normal-only fit)  │
                    │           plus max-score combination          │
                    └───────────────────────┬────────────────────────┘
                                             │ risk score 0-100 + explanation
                                             ▼
                    ┌──────────────────────────────────────────────┐
                    │  API  (threat_detection.api, FastAPI)          │
                    │  /health, /score[/source], /events, /demo/replay│
                    │  compact score history → local SQLite          │
                    └───────────────────────┬────────────────────────┘
                                             │ JSON
                                             ▼
                    ┌──────────────────────────────────────────────┐
                    │ Analyst Dashboard (synthetic demo implemented) │
                    └──────────────────────────────────────────────┘
```

Each layer is a separate Python package behind an abstract interface (`EventSource`,
`FeatureExtractor`, `AnomalyDetector`), so layers can be developed, tested, and reasoned about
independently, and a layer's concrete implementation can be swapped without touching the
others — e.g. swapping the synthetic generator for a real feed later only touches `ingestion`.

## 2. Data flow (implemented prototype)

1. Synthetic `EventSource` emits one event at a time (LOGIN, ORDER, CANCEL_ORDER, API_REQUEST,
   ...), a handful of simulated accounts, a few with planted attacks carrying `is_attack` /
   `attack_type` ground truth (never passed to the detector — evaluation-only).
2. `FeatureExtractor` maintains rolling per-account state (count, mean, variance via a
   streaming/Welford-style update — no need to store full history) and emits a feature vector
   per event.
3. The z-score detector computes interpretable statistical alerts. A fitted Isolation Forest
   scores the same feature vector. The API uses the maximum of their 0–100 alert scores and
   returns both component scores. A Forest-only outlier gets the minimum review score (50),
   not an unsupported high-severity score; the attack-type guess remains the z-score layer's guess.
   Forest scoring is suppressed until the account has prior event history, avoiding cold-start
   alerts before a per-account baseline can exist.
4. `POST /score` accepts one event, rejects `is_attack` and `attack_type`, then returns
   `{risk_score, explanation, attack_type_guess, layer_scores}` as JSON. At module import,
   the demo forest is fit on one normal-only synthetic stream and calibrated on a separate
   normal-only stream. Both use fixed seeds; the fitted model is process-local.
5. Each scored event's compact analyst summary is saved to local SQLite (default
   `data/events.sqlite3`, configurable with `THREAT_DETECTION_DB_PATH`). The `/events`
   endpoint reads the newest 500 summaries. Raw event payloads and evaluation labels are
   not stored. Event history survives process restarts, while rolling per-account feature
   state and the fitted demo model do not. Synthetic replay uses its own feature extractor
   so a demo run does not reset or contaminate `/score`'s rolling account state.

## 3. What's implemented, abstract, and still required

- `NormalizedEvent` is the shared broker-neutral contract. `ConfiguredFieldMapAdapter` handles flat field/type aliases and can be enabled for `/score/source` with startup environment settings; `BrokerEventAdapter` is the extension point for custom mappings. No provider-specific mapping or connection is implemented.
- The `EventSource`, `FeatureExtractor`, and `AnomalyDetector` base classes are abstract contracts, not runnable implementations.
- Concrete implementations exist for the synthetic source, rolling statistics extractor, z-score detector, Isolation Forest detector, and max-score ensemble.
- Autoencoder comparison method (`DECISIONS.md` §5)
- Bounded local SQLite history of compact score summaries (implemented); production-secured
  storage, cross-process coordination, and persistence of rolling feature/model state remain
  future work
- Local browser dashboard for synthetic replay and normalized-event scoring, with explanations
  and recent history (implemented for local demo)
- Push-based WebSocket/SSE updates (optional; polling is sufficient for the first working UI)
- Graph-based fraud-ring detection, adversarial evasion testing (`DECISIONS.md` §9)

The backend and dashboard demonstrate feasibility, not broker deployment. There is no live
broker data source or production deployment; only the compact score history persists locally.
The broker must provide an authorized adapter that maps its telemetry to the normalized event
contract. The local SQLite database has no authentication or encryption and must not be
exposed as production broker storage. See `PROGRESS.md` for remaining work and
`EVALUATION_BASELINE.md` for detector measurements and caveats.

## 4. Component selection summary

See `DECISIONS.md` §7 for the current status and rationale. Summary:

| Component | Choice | One-line why |
|---|---|---|
| API framework | FastAPI | Async, Pydantic validation, native WebSocket support for later dashboard |
| Detection (statistical) | Rolling z-score | Interpretable, zero training data, cheap in real time |
| Detection signals | Rolling z-score + Isolation Forest signal | Current backend combines risk signals; internal component metrics support validation |
| Containerization | Docker | Reproducible for grading/demo |
| Architecture style | Modular monolith | No premature microservices; extract only where load-tested |
