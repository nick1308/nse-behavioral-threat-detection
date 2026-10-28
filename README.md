# NSE Behavioral Threat Detection

IDP project: a real-time behavioral threat detection prototype for a simulated
Indian retail trading platform. It learns account and API-client baselines,
scores unusual events, and returns an explainable 0–100 risk score.

Current standing, measured results, limitations, and a finish plan are in
[PROGRESS.md](PROGRESS.md). This is a tested feasibility prototype, not a
production deployment; its evaluation uses synthetic planted patterns.

## Current implementation

- `ingestion/`: canonical `NormalizedEvent` contract, abstract broker adapter
  extension point, configurable flat-field mapper, and seeded synthetic source
  with account takeover, API abuse, and automated trading scenarios. No
  broker-specific mapping or live connection is included.
- `features/`: online order-size/value statistics, account device and login
  history, per-client request rates, matched order-cancel timing, and Indian
  regular-session context.
- `detection/`: explainable rolling z-score rules plus a separately fitted
  Isolation Forest anomaly layer. The API combines them by taking the larger
  score and returns both layer scores; a Forest-only outlier reaches the review
  threshold but is not promoted to high severity; the Forest does not assign
  attack types.
- `evaluation/`: ground-truth-safe replay, clean-stream model fitting and
  calibration, scenario and event recall, false-positive rate, per-attack-type
  recall, and per-event processing latency.
- `api/`: FastAPI `/health`, `/score`, optional mapped `/score/source`, `/events`,
  and synthetic replay endpoints, plus the local dashboard and bounded SQLite
  event-summary history.

The ingestion `base.py` defines `EventSource` and `BrokerEventAdapter` contracts;
the feature and detection `base.py` files define `FeatureExtractor` and
`AnomalyDetector`. `NormalizedEvent` is the shared input model. At API import, the demo Forest is fit and calibrated
on separate, reproducible normal-only synthetic streams. The model remains in
memory for that process, and Forest scoring is held during account cold start.
The local analyst dashboard connects to the API, replays synthetic events,
accepts one normalized JSON event for scoring, and shows scores, reasons, and
recent history. A broker-specific adapter must map source fields to the
canonical event before submission; the UI does not connect to a broker. Recent
score summaries persist in local SQLite at `data/events.sqlite3` by default;
set `THREAT_DETECTION_DB_PATH` to choose another file. Rolling feature state
and the fitted demo model remain process-local, and SQLite history has no
authentication or encryption, so this is for local demonstration only. A
production broker deployment needs secured storage, access control, retention
policy, and durable baseline/model lifecycle. Kafka, graph-based fraud rings,
and adversarial evasion tests remain future work.

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
Run the curated magnitude/timing challenge cases with
`$env:PYTHONPATH = "src"; .\.venv\Scripts\python.exe -m threat_detection.evaluation.variants`;
these remain synthetic checks, not independent broker validation.

## Run the API locally

```powershell
uvicorn threat_detection.api.main:app --app-dir src --reload
```

To enable flat source-event mapping, set the canonical-to-source field map
before starting the API. This example expects `id`, `trading_account`,
`occurred_at`, `action`, and `session` fields and maps `TRADE_EXECUTED` to
`ORDER`:

```powershell
$env:THREAT_DETECTION_FIELD_MAP = '{"event_id":"id","account_id":"trading_account","timestamp":"occurred_at","event_type":"action","session_id":"session","order_value":"amount"}'
$env:THREAT_DETECTION_EVENT_TYPE_MAP = '{"TRADE_EXECUTED":"ORDER"}'
$env:THREAT_DETECTION_API_KEY = (& .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))").Trim()
```

In the same PowerShell session, start the API with the command above. Then send
a flat mapped event to `POST /score/source`. The route is disabled
without a mapping and bearer key. Send the key in the `Authorization: Bearer`
header. The route does not establish a broker connection or support nested
payload transformations. The static key gate is a local integration safeguard,
not production identity management; use a managed authentication layer before
exposing the API to a broker network.

Then open `http://localhost:8000/docs` or check `http://localhost:8000/health`.
The analyst dashboard is at `http://localhost:8000/`.

## Run with Docker

```powershell
docker build -t threat-detection .
docker run -p 8000:8000 -v threat-detection-data:/app/data threat-detection
```

The named Docker volume retains local SQLite score history across container
recreation. It does not persist rolling feature state or provide production
data protection.

## Team

Three-person IDP team, Aug 2026–Mar 2027.
