"""TOTP verification with per-user clock drift tracking.

A one time password is bound to a time step.  A slowly drifting phone clock
moves the step at which the user's code was produced, so verification looks at
a window of candidate steps around the expected one and remembers the drift it
has observed for that user.
"""

import hashlib
import hmac
import struct

# Hard upper bound for the candidate window radius, in steps.
MAX_WINDOW = 10


def step_of(now, period, offset=0):
    """Return the time step for a unix timestamp plus a drift offset in steps."""
    if isinstance(period, bool) or not isinstance(period, int) or period <= 0:
        raise ValueError("period must be a positive integer number of seconds")
    if isinstance(now, bool) or not isinstance(now, int):
        raise ValueError("now must be an integer number of unix seconds")
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise ValueError("offset must be an integer number of steps")
    return now // period + offset


def candidates(step, window):
    """Return candidate steps around a step within a symmetric radius."""
    if isinstance(window, bool) or not isinstance(window, int):
        raise ValueError("window must be an integer number of steps")
    if window < 0:
        raise ValueError("window must be non-negative")
    if isinstance(step, bool) or not isinstance(step, int):
        raise ValueError("step must be an integer")
    radius = min(window, MAX_WINDOW)
    return [step + delta for delta in range(-radius, radius + 1)]


def code_at(secret, step, digits=6):
    """Return the decimal one time code for a secret and a step."""
    if isinstance(step, bool) or not isinstance(step, int) or step < 0:
        raise ValueError("step must be a non-negative integer")
    if isinstance(digits, bool) or not isinstance(digits, int) or digits <= 0:
        raise ValueError("digits must be a positive integer")
    key = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    base = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[base:base + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def match(code, secret, candidates, digits=6):
    """Return the first candidate step whose code matches, or -1."""
    if not isinstance(code, str) or code == "":
        return -1
    if isinstance(digits, bool) or not isinstance(digits, int) or digits <= 0:
        raise ValueError("digits must be a positive integer")
    for step in candidates:
        if step < 0:
            continue
        expected = code_at(secret, step, digits)
        if expected == code:
            return step
    return -1


def update_offset(state, matched_step, expected_step, policy, now):
    """Adjust the recorded drift offset after a successful validation."""
    limit = abs(int(policy.get("max_offset", 0)))
    offset = int(state.get("offset", 0))
    if matched_step is None or int(matched_step) < 0:
        return {"ok": False, "offset": offset, "delta": 0, "at": int(now)}
    delta = int(matched_step) - int(expected_step)
    # Reset to the drift observed this time; never accumulate or keep old drift.
    offset = max(-limit, min(limit, delta))
    state["offset"] = offset
    state["last_adjusted"] = int(now)
    return {"ok": True, "offset": offset, "delta": delta, "at": int(now)}


def consume_step(state, step):
    """Consume a time step so that a code for it cannot be used again."""
    step = int(step)
    if step < 0:
        return {
            "ok": False,
            "step": step,
            "count": int(state.get("count", 0)),
            "reason": "negative step",
        }
    used = state.setdefault("used", set())
    count = int(state.get("count", 0))
    current = int(state.get("current", 0))
    if step in used:
        return {"ok": False, "step": step, "count": count, "reason": "step already used"}
    used.add(step)
    count += 1
    state["count"] = count
    current = max(current, step)
    state["current"] = current
    window = int(state.get("window", 0))
    horizon = current - window
    stale = [seen for seen in used if seen < horizon]
    for seen in stale:
        used.discard(seen)
    return {"ok": True, "step": step, "count": count, "reason": "ok"}


def validate_state(state, policy):
    """Return a list of human readable problems found in the drift state."""
    problems = []
    used = set(state.get("used", set()))
    current = int(state.get("current", 0))
    limit = abs(int(policy.get("max_offset", 0)))
    if abs(int(state.get("offset", 0))) > limit:
        problems.append("offset outside policy limit: " + str(state.get("offset", 0)))
    for step in sorted(used):
        if step > current:
            problems.append("used step ahead of current: " + str(step))
    last = state.get("last_adjusted")
    seen = state.get("now")
    if last is not None and seen is not None and int(last) > int(seen):
        problems.append("last adjustment later than now: " + str(last))
    return problems


def drift_batch(attempts, policy):
    """Validate a batch of one time codes, one drift state per user."""
    period = int(policy["period"])
    window = int(policy["window"])
    radius = min(window, MAX_WINDOW)
    digits = int(policy.get("digits", 6))
    states = {}
    results = []
    total = 0
    for item in attempts:
        user = item["user"]
        state = states.get(user)
        if state is None:
            state = {
                "offset": 0,
                "used": set(),
                "count": 0,
                "current": 0,
                "window": radius,
                "last_adjusted": None,
                "now": int(item["now"]),
            }
            states[user] = state
        state["now"] = int(item["now"])
        expected = step_of(int(item["now"]), period)
        center = expected + int(state["offset"])
        matched = match(item["code"], item["secret"], candidates(center, window), digits)
        if matched < 0:
            results.append(
                {
                    "user": user,
                    "ok": False,
                    "step": -1,
                    "count": state["count"],
                    "reason": "no match",
                }
            )
            continue
        consumed = consume_step(state, matched)
        if not consumed["ok"]:
            results.append(
                {
                    "user": user,
                    "ok": False,
                    "step": matched,
                    "count": consumed["count"],
                    "reason": consumed["reason"],
                }
            )
            continue
        update_offset(state, matched, expected, policy, int(item["now"]))
        total += 1
        results.append(
            {
                "user": user,
                "ok": True,
                "step": matched,
                "count": consumed["count"],
                "reason": "ok",
            }
        )
    return {"results": results, "count": total}