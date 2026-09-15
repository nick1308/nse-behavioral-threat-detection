# System Design

Real-Time Behavioral Threat Detection for Trading Systems — IDP, Review 2

Rationale for every component choice below is in `DECISIONS.md`; this document is the
architecture and data-flow view, cross-referenced back to those decisions.

## 1. Architecture diagram

```
                    ┌──────────────────────────────────────────────┐
                    │           Simulated Trading Platform          │
                    │   (synthetic event generator, Review-2 scope) │
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
                    │  Layer 2: Isolation Forest (future scope beyond│
                    │           Review 2 — see DECISIONS.md §3)      │
                    └───────────────────────┬────────────────────────┘
                                             │ risk score 0-100 + explanation
                                             ▼
                    ┌──────────────────────────────────────────────┐
                    │  API  (threat_detection.api, FastAPI)          │
                    │  /health, /score (Review-2 scope)              │
                    │  WebSocket alert feed — future scope           │
                    └───────────────────────┬────────────────────────┘
                                             │ JSON
                                             ▼
                    ┌──────────────────────────────────────────────┐
                    │      Analyst Dashboard (React) — future scope  │
                    └──────────────────────────────────────────────┘
```

Each layer is a separate Python package behind an abstract interface (`EventSource`,
`FeatureExtractor`, `AnomalyDetector`), so layers can be developed, tested, and reasoned about
independently, and a layer's concrete implementation can be swapped without touching the
others — e.g. swapping the synthetic generator for a real feed later only touches `ingestion`.

## 2. Data flow (Review 2 prototype scope)

1. Synthetic `EventSource` emits one event at a time (LOGIN, ORDER, CANCEL_ORDER, API_REQUEST,
   ...), a handful of simulated accounts, a few with planted attacks carrying `is_attack` /
   `attack_type` ground truth (never passed to the detector — evaluation-only).
2. `FeatureExtractor` maintains rolling per-account state (count, mean, variance via a
   streaming/Welford-style update — no need to store full history) and emits a feature vector
   per event.
3. `AnomalyDetector` (statistical layer only, for Review 2) computes a z-score per feature,
   combines into a 0–100 risk score, and attaches a plain-English explanation string.
4. `POST /score` accepts an event (or triggers the generator for a demo event), runs it through
   steps 2–3, returns `{risk_score, explanation, attack_type_guess}` as JSON.

## 3. What's explicitly deferred past Review 2

- Isolation Forest layer (interface exists, concrete implementation is future work — `DECISIONS.md` §3, §9)
- Autoencoder comparison method (`DECISIONS.md` §5)
- PostgreSQL/TimescaleDB persistence, Redis caching (currently in-memory only, sufficient for
  a single-process prototype; DB introduced when persistence/multi-process state is needed)
- React dashboard, WebSocket live feed
- Graph-based fraud-ring detection, adversarial evasion testing (`DECISIONS.md` §9)

This scoping is deliberate: Review 2 asks for ~20% completion, requirement analysis, design,
component selection, and a feasibility-demonstrating prototype — not a finished product. The
vertical slice above (generator → features → statistical detection → API) is the smallest
complete path that actually proves the pipeline concept works, rather than a wider set of
disconnected stubs.

## 4. Component selection summary

See `DECISIONS.md` §7 for the full table and reasoning. Summary for Review 2 talking points:

| Component | Choice | One-line why |
|---|---|---|
| API framework | FastAPI | Async, Pydantic validation, native WebSocket support for later dashboard |
| Detection (statistical) | Rolling z-score | Interpretable, zero training data, cheap in real time |
| Detection (ML, future) | Isolation Forest | No labeled fraud data needed; linear time; well-established (Liu et al. 2008) |
| Containerization | Docker | Reproducible for grading/demo |
| Architecture style | Modular monolith | No premature microservices; extract only where load-tested |
