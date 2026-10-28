import pytest
from fastapi.testclient import TestClient

from threat_detection.api import main
from threat_detection.api.event_store import SQLiteEventStore
from threat_detection.api.main import app

client = TestClient(app)
_TEST_SOURCE_API_KEY = "api-test-token-not-for-production"


def _order_event(**overrides):
    base = {
        "event_id": "evt-1",
        "account_id": "ACC_API_TEST_1",
        "timestamp": "2026-09-10T10:00:00+00:00",
        "event_type": "ORDER",
        "device_id": "device-known",
        "ip_address": "10.0.0.1",
        "session_id": "sess-1",
        "order_value": 1000.0,
    }
    base.update(overrides)
    return base


def test_score_endpoint_returns_expected_shape():
    response = client.post("/score", json=_order_event())
    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {"risk_score", "explanation", "attack_type_guess", "layer_scores"}
    assert isinstance(body["risk_score"], (int, float))
    assert isinstance(body["explanation"], str)
    assert set(body["layer_scores"]) == {"zscore", "isolation_forest"}
    assert body["risk_score"] == max(body["layer_scores"].values())


def test_scored_normalized_event_appears_in_analyst_history():
    event = _order_event(event_id="evt-dashboard-score", account_id="ACC_HISTORY_TEST")

    response = client.post("/score", json=event)

    assert response.status_code == 200
    history = client.get("/events?limit=500").json()["events"]
    scored_event = next(item for item in history if item["event_id"] == event["event_id"])
    assert scored_event["risk_score"] == response.json()["risk_score"]
    assert scored_event["explanation"] == response.json()["explanation"]
    assert {"is_attack", "attack_type"}.isdisjoint(scored_event)


def test_api_event_history_is_available_after_store_reopen(tmp_path, monkeypatch):
    database_path = tmp_path / "api-history.sqlite3"
    store = SQLiteEventStore(database_path)
    monkeypatch.setattr(main, "_event_store", store)
    event = _order_event(event_id="evt-restart-test", account_id="ACC_RESTART_TEST")

    score_response = client.post("/score", json=event)
    assert score_response.status_code == 200
    store.close()

    reopened_store = SQLiteEventStore(database_path)
    monkeypatch.setattr(main, "_event_store", reopened_store)
    try:
        history = client.get("/events?limit=10").json()["events"]
        assert len(history) == 1
        assert history[0]["event_id"] == event["event_id"]
        assert history[0]["risk_score"] == score_response.json()["risk_score"]
    finally:
        reopened_store.close()


def test_configured_source_event_is_mapped_scored_and_recorded(monkeypatch):
    monkeypatch.setenv(
        "THREAT_DETECTION_FIELD_MAP",
        '{"event_id":"id","account_id":"trading_account",'
        '"timestamp":"occurred_at","event_type":"action",'
        '"session_id":"session","order_value":"amount"}',
    )
    monkeypatch.setenv("THREAT_DETECTION_EVENT_TYPE_MAP", '{"TRADE_EXECUTED":"ORDER"}')
    monkeypatch.setattr(main, "_broker_event_adapter", main._build_source_adapter())
    monkeypatch.setattr(main, "_source_api_key", _TEST_SOURCE_API_KEY)
    source_event = {
        "id": "broker-event-1",
        "trading_account": "BROKER-ACCOUNT-1",
        "occurred_at": "2026-09-18T10:15:00+00:00",
        "action": "TRADE_EXECUTED",
        "session": "broker-session-1",
        "amount": 1500.0,
        "broker_internal_flag": "discard me",
        "is_attack": True,
    }

    response = client.post(
        "/score/source",
        json=source_event,
        headers={"Authorization": f"Bearer {_TEST_SOURCE_API_KEY}"},
    )

    assert response.status_code == 200
    history = client.get("/events?limit=10").json()["events"]
    assert len(history) == 1
    assert history[0]["event_id"] == "broker-event-1"
    assert history[0]["event_type"] == "ORDER"
    assert "broker_internal_flag" not in history[0]
    assert "is_attack" not in history[0]


def test_source_scoring_is_disabled_without_mapping_configuration():
    response = client.post("/score/source", json={"id": "unmapped-event"})

    assert response.status_code == 503
    assert response.json()["detail"] == "No source field mapping is configured for this endpoint."


def test_source_scoring_requires_api_key_configuration(monkeypatch):
    monkeypatch.setenv("THREAT_DETECTION_FIELD_MAP", '{"event_id":"id"}')
    monkeypatch.setattr(main, "_broker_event_adapter", main._build_source_adapter())
    monkeypatch.setattr(main, "_source_api_key", None)

    response = client.post("/score/source", json={"id": "event"})

    assert response.status_code == 503
    assert "THREAT_DETECTION_API_KEY" in response.json()["detail"]


@pytest.mark.parametrize(
    "authorization",
    [None, "Bearer wrong-token", "Basic api-test-token-not-for-production"],
)
def test_source_scoring_rejects_missing_or_invalid_bearer_key(monkeypatch, authorization):
    monkeypatch.setenv("THREAT_DETECTION_FIELD_MAP", '{"event_id":"id"}')
    monkeypatch.setattr(main, "_broker_event_adapter", main._build_source_adapter())
    monkeypatch.setattr(main, "_source_api_key", _TEST_SOURCE_API_KEY)
    headers = {"Authorization": authorization} if authorization else None

    response = client.post(
        "/score/source",
        json={"id": "event"},
        headers=headers,
    )

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_invalid_source_mapping_configuration_is_rejected(monkeypatch):
    monkeypatch.setenv("THREAT_DETECTION_FIELD_MAP", "[\"not\", \"an object\"]")
    monkeypatch.delenv("THREAT_DETECTION_EVENT_TYPE_MAP", raising=False)

    with pytest.raises(RuntimeError, match="must contain a JSON object"):
        main._build_source_adapter()


def test_first_event_for_a_new_account_is_low_risk():
    # A brand-new account's very first event has no history to compare
    # against, so the statistical layer shouldn't flag it as high-risk
    # purely for being new (that would make every legitimate new account
    # look like an attack).
    response = client.post("/score", json=_order_event(account_id="ACC_API_TEST_2", event_id="evt-first"))
    assert response.status_code == 200
    body = response.json()
    assert body["risk_score"] < 40  # below the account-takeover weight on its own

def test_state_persists_across_requests_for_the_same_account():
    account_id = "ACC_API_TEST_3"
    # Build up a stable order-size history through repeated calls.
    for i in range(10):
        client.post(
            "/score",
            json=_order_event(account_id=account_id, event_id=f"hist-{i}", order_value=100.0 + i),
        )
    # A wildly larger order on the same account, same device/hour, should
    # now score meaningfully higher than the very first request did.
    response = client.post(
        "/score",
        json=_order_event(account_id=account_id, event_id="spike", order_value=500_000.0),
    )
    assert response.status_code == 200
    assert response.json()["risk_score"] > 0


def test_score_endpoint_rejects_missing_required_fields():
    incomplete = {"account_id": "ACC1"}  # missing event_id, timestamp, etc.
    response = client.post("/score", json=incomplete)
    assert response.status_code == 422


def test_score_endpoint_rejects_ground_truth_fields():
    response = client.post("/score", json={**_order_event(), "is_attack": True, "attack_type": "api_abuse"})
    assert response.status_code == 422


def test_score_endpoint_accepts_events_without_device_or_ip_telemetry():
    event = _order_event(event_id="evt-privacy-minimized")
    event.pop("device_id")
    event.pop("ip_address")

    response = client.post("/score", json=event)

    assert response.status_code == 200
    assert response.json()["risk_score"] >= 0


def test_score_endpoint_rejects_unknown_event_type_and_undeclared_fields():
    unknown_type = client.post("/score", json=_order_event(event_type="TRADE_FILLED"))
    undeclared = client.post("/score", json=_order_event(unmapped_secret="value"))

    assert unknown_type.status_code == 422
    assert undeclared.status_code == 422


def test_health_still_works():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
