"""Public tests for the totp drift engine."""

from engine.totp import (
    candidates,
    code_at,
    consume_step,
    drift_batch,
    match,
    step_of,
    update_offset,
)

NOW = 1_700_000_000


def make_policy(window=2, max_offset=3, period=30, digits=6):
    return {"period": period, "window": window, "max_offset": max_offset, "digits": digits}


def make_state(current=0, window=1, offset=0, used=None):
    return {
        "offset": offset,
        "used": set() if used is None else set(used),
        "count": 0,
        "current": current,
        "window": window,
        "last_adjusted": None,
        "now": NOW,
    }


def test_candidates_are_symmetric():
    assert candidates(500, 2) == [498, 499, 500, 501, 502]

    secret = "PUBSYM"
    slow_code = code_at(secret, 498, 6)

    assert match(slow_code, secret, candidates(500, 2), 6) == 498


def test_offset_adjusts_to_observed_drift():
    policy = make_policy(window=2, max_offset=5)
    state = make_state(current=2000, offset=1)

    outcome = update_offset(state, 2002, 2000, policy, NOW)

    assert outcome["ok"] is True
    assert outcome["delta"] == 2
    assert outcome["offset"] == 2
    assert state["offset"] == 2


def test_offset_capped_by_policy():
    policy = make_policy(window=3, max_offset=2)
    above = make_state(current=3000)
    below = make_state(current=3000)

    up = update_offset(above, 3007, 3000, policy, NOW)
    down = update_offset(below, 2993, 3000, policy, NOW)

    assert up["offset"] == 2
    assert above["offset"] == 2
    assert down["offset"] == -2
    assert below["offset"] == -2


def test_same_step_succeeds_once():
    state = make_state(current=42, window=1)

    first = consume_step(state, 42)
    second = consume_step(state, 42)

    assert first["ok"] is True
    assert second["ok"] is False
    assert state["used"] == {42}
    assert state["count"] == 1


def test_batch_users_keep_their_own_offset():
    period = 30
    policy = {"period": period, "window": 2, "max_offset": 4, "digits": 6}
    now_a = 1_700_000_010
    now_b = 1_700_000_040
    step_a = step_of(now_a, period)
    step_b = step_of(now_b, period)

    attempts = [
        {"user": "anna", "secret": "PUBAAA", "now": now_a, "code": code_at("PUBAAA", step_a + 2, 6)},
        {"user": "ben", "secret": "PUBBBB", "now": now_b, "code": code_at("PUBBBB", step_b, 6)},
    ]

    outcome = drift_batch(attempts, policy)

    assert [item["ok"] for item in outcome["results"]] == [True, True]
    assert outcome["results"][0]["step"] == step_a + 2
    assert outcome["results"][1]["step"] == step_b
    assert outcome["count"] == 2