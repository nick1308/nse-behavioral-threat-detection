from fastapi.testclient import TestClient

from threat_detection.api import main
from threat_detection.api.main import app


client = TestClient(app)


def test_dashboard_and_assets_are_served():
    page = client.get("/")
    stylesheet = client.get("/dashboard.css")
    script = client.get("/dashboard.js")

    assert page.status_code == 200
    assert "Run demo stream" in page.text
    assert "Score one event" in page.text
    assert "does not connect to a broker" in page.text
    assert stylesheet.status_code == 200
    assert "stat-grid" in stylesheet.text
    assert script.status_code == 200
    assert "demo/replay" in script.text
    assert "fetch('/score'" in script.text


def test_demo_replay_scores_events_and_keeps_ground_truth_out_of_ui_api():
    replay = client.post("/demo/replay?seed=42")

    assert replay.status_code == 200
    replay_result = replay.json()
    assert replay_result["processed_events"] > 0
    assert replay_result["alert_count"] >= 0

    event_response = client.get("/events?limit=500")
    assert event_response.status_code == 200
    events = event_response.json()["events"]
    assert len(events) == replay_result["processed_events"]
    assert events
    assert {"is_attack", "attack_type"}.isdisjoint(events[0])
    assert {
        "event_id",
        "account_id",
        "timestamp",
        "event_type",
        "risk_score",
        "explanation",
        "attack_type_guess",
        "layer_scores",
    } == set(events[0])


def test_event_history_limit_is_bounded():
    response = client.get("/events?limit=501")
    assert response.status_code == 422


def test_demo_replay_is_repeatable_for_the_same_seed():
    first_replay = client.post("/demo/replay?seed=42").json()
    first_events = client.get("/events?limit=500").json()["events"]

    second_replay = client.post("/demo/replay?seed=42").json()
    second_events = client.get("/events?limit=500").json()["events"]

    assert second_replay == first_replay
    assert second_events == first_events


def test_demo_replay_does_not_replace_live_feature_state():
    live_feature_extractor = main._feature_extractor

    response = client.post("/demo/replay?seed=42")

    assert response.status_code == 200
    assert main._feature_extractor is live_feature_extractor
