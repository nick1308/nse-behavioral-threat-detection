from datetime import datetime, timezone

from threat_detection.ingestion.synthetic import SyntheticEventSource


def test_planted_api_abuse_reuses_a_client_with_normal_history():
    events = list(
        SyntheticEventSource(
            num_accounts=3,
            num_attack_accounts=3,
            events_per_normal_account=5,
            seed=17,
            start_time=datetime(2026, 9, 1, tzinfo=timezone.utc),
        ).events()
    )
    attack_requests = [
        event
        for event in events
        if event["event_type"] == "API_REQUEST"
        and event.get("attack_type") == "api_abuse"
    ]

    assert attack_requests
    attacked_client = attack_requests[0]["client_id"]
    account_id = attack_requests[0]["account_id"]
    normal_requests = [
        event
        for event in events
        if event["event_type"] == "API_REQUEST"
        and not event["is_attack"]
        and event["account_id"] == account_id
        and event["client_id"] == attacked_client
    ]
    assert len(normal_requests) == 3
    assert max(event["timestamp"] for event in normal_requests) < min(
        event["timestamp"] for event in attack_requests
    )
