# nse-behavioral-threat-detection

IDP — Real-Time Behavioral Threat Detection for Trading Systems

A simulated trading platform instrumented to detect anomalous/malicious trader
behavior in real time. Pipeline: **event ingestion → behavioral feature
extraction → anomaly detection (statistical baseline + Isolation Forest) →
explainable risk scoring → analyst dashboard**.

> Status: repository skeleton only. Layers contain interfaces/placeholders,
> not the working pipeline yet.

## Structure

```
src/threat_detection/
  ingestion/    # reads raw trading events from a source (EventSource interface)
  features/     # turns raw events into behavioral feature vectors (FeatureExtractor interface)
  detection/    # scores feature vectors for anomalousness (AnomalyDetector interface)
  api/          # FastAPI app that exposes results to the analyst dashboard
tests/          # pytest suite, mirrors src/ layout one package per layer
Dockerfile
requirements.txt       # runtime deps
requirements-dev.txt   # runtime + test deps
pytest.ini
```

Each layer is a separate package so ingestion, feature extraction, detection,
and the API can be developed, tested, and reasoned about independently. The
`base.py` in each package defines the abstract interface that concrete
implementations (added later) will follow.

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements-dev.txt
```

## Run tests

```bash
pytest
```

## Run the API locally

```bash
uvicorn threat_detection.api.main:app --app-dir src --reload
```

Then check `http://localhost:8000/health`.

## Run with Docker

```bash
docker build -t threat-detection .
docker run -p 8000:8000 threat-detection
```

## Team

3-person team, Aug 2026–Feb/Mar 2027 IDP project.
