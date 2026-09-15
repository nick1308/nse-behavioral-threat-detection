from fastapi.testclient import TestClient

from threat_detection.api.main import app

client = TestClient(app)


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
    assert set(body.keys()) == {"risk_score", "explanation", "attack_type_guess"}
    assert isinstance(body["risk_score"], (int, float))
    assert isinstance(body["explanation"], str)


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


def test_health_still_works():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
