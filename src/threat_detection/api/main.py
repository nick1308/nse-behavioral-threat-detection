"""FastAPI application entry point."""

from fastapi import FastAPI

app = FastAPI(title="NSE Behavioral Threat Detection", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness check used by Docker/orchestration and by tests."""
    return {"status": "ok"}
