# NSE Behavioral Threat Detection

IDP project: a real-time behavioral threat detection prototype for a simulated
Indian retail trading platform. It learns account and API-client baselines,
scores unusual events, and returns an explainable 0–100 risk score.

## Current implementation

- `ingestion/`: seeded synthetic event source with account takeover, API abuse,
  and automated trading scenarios.
- `features/`: online order-size/value statistics, account device and login
  history, per-client request rates, matched order-cancel timing, and Indian
  regular-session context.
- `detection/`: explainable rolling z-score rules plus a separately fitted
  Isolation Forest anomaly layer. The API combines them by taking the larger
  score and returns both layer scores; the Forest does not assign attack types.
- `evaluation/`: ground-truth-safe replay, clean-stream model fitting and
  calibration, scenario and event recall, false-positive rate, per-attack-type
  recall, and per-event processing latency.
- `api/`: FastAPI `/health` and `/score` endpoints.

The `base.py` files define the stable `EventSource`, `FeatureExtractor`, and
`AnomalyDetector` contracts. At API import, the demo Forest is fit and calibrated
on separate, reproducible normal-only synthetic streams. The model remains in
memory for that process, and Forest scoring is held during account cold start.
Persistence, Kafka, a dashboard, graph-based fraud rings, and adversarial evasion
tests are outside the current prototype scope.

## Setup

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
```

## Run tests

```powershell
pytest -q
```

## Run the fixed-seed evaluation

```powershell
$env:PYTHONPATH = "src"
python -m threat_detection.evaluation
```

The command reports z-score, Isolation Forest, and combined results on the same
fixed evaluation seed. The forest is fit on a separate normal-only stream and its
alert cutoff is calibrated on another normal-only stream. Read measured results
and limitations in [docs/EVALUATION_BASELINE.md](docs/EVALUATION_BASELINE.md).

## Run the API locally

```powershell
uvicorn threat_detection.api.main:app --app-dir src --reload
```

Then open `http://localhost:8000/docs` or check `http://localhost:8000/health`.

## Run with Docker

```powershell
docker build -t threat-detection .
docker run -p 8000:8000 threat-detection
```

## Team

Three-person IDP team, Aug 2026–Mar 2027.
