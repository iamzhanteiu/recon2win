"""Tests for telegram.notify_stage_result().

We mock ``_post`` so no real HTTP traffic is generated, then verify:
  * telegram-disabled / missing config  → no call
  * non-success status                   → no call
  * count <= 0                           → no call
  * nuclei stage                          → severity breakdown
  * content_discovery                     → URL count + JS count
  * generic stage                         → generic message
"""
from unittest.mock import patch

import pytest

from modules.telegram import notify_stage_result


# ----------------------------------------------------------------------
# fixtures / helpers
# ----------------------------------------------------------------------
def _cfg(enabled: bool = True) -> dict:
    return {
        "enabled": enabled,
        "bot_token": "T",
        "chat_id": "C",
        "notify_high_critical": True,
    }


# ----------------------------------------------------------------------
# guard clauses
# ----------------------------------------------------------------------
def test_returns_false_when_telegram_disabled():
    res = {"status": "success", "count": 5}
    with patch("modules.telegram._post") as post:
        assert notify_stage_result("nuclei_default", res, _cfg(enabled=False)) is False
        post.assert_not_called()


def test_returns_false_when_cfg_missing_token():
    cfg = {"enabled": True, "bot_token": "", "chat_id": "C"}
    res = {"status": "success", "count": 5}
    with patch("modules.telegram._post") as post:
        assert notify_stage_result("nuclei_default", res, cfg) is False
        post.assert_not_called()


def test_returns_false_when_status_not_success():
    with patch("modules.telegram._post") as post:
        for status in ("failed", "skipped"):
            res = {"status": status, "count": 5}
            assert notify_stage_result("nuclei_default", res, _cfg()) is False
        post.assert_not_called()


@pytest.mark.parametrize("count", [0, -1, None])
def test_returns_false_when_count_is_zero_or_negative(count):
    with patch("modules.telegram._post") as post:
        res = {"status": "success", "count": count}
        assert notify_stage_result("nuclei_default", res, _cfg()) is False
        post.assert_not_called()


def test_returns_false_when_result_not_dict():
    with patch("modules.telegram._post") as post:
        assert notify_stage_result("nuclei_default", "not-a-dict", _cfg()) is False
        assert notify_stage_result("nuclei_default", None, _cfg()) is False
        post.assert_not_called()


# ----------------------------------------------------------------------
# nuclei — severity breakdown
# ----------------------------------------------------------------------
def test_nuclei_default_message_has_severity_breakdown():
    result = {
        "status": "success",
        "count": 7,
        "extra": {
            "severity_count": {
                "critical": 1, "high": 2, "medium": 3, "low": 1, "info": 0,
            }
        },
    }
    with patch("modules.telegram._post") as post:
        post.return_value = True
        assert notify_stage_result("nuclei_default", result, _cfg()) is True
        post.assert_called_once()
        # _post(token, chat_id, text)
        token, chat, msg = post.call_args[0]
        assert token == "T"
        assert chat == "C"
        assert "nuclei_default" in msg
        assert "<code>7</code>" in msg
        assert "critical" in msg and "<code>1</code>" in msg
        assert "high" in msg and "<code>2</code>" in msg
        assert "medium" in msg and "<code>3</code>" in msg
        assert "low" in msg and "<code>1</code>" in msg
        assert "info" in msg and "<code>0</code>" in msg


def test_nuclei_dynamic_uses_same_format():
    result = {
        "status": "success",
        "count": 2,
        "extra": {"severity_count": {"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0}},
    }
    with patch("modules.telegram._post") as post:
        post.return_value = True
        assert notify_stage_result("nuclei_dynamic", result, _cfg()) is True
        msg = post.call_args[0][2]
        assert "nuclei_dynamic" in msg
        assert "<code>2</code>" in msg
        assert "high" in msg and "<code>2</code>" in msg


def test_nuclei_handles_missing_severity_count_gracefully():
    result = {"status": "success", "count": 3, "extra": {}}  # no severity_count
    with patch("modules.telegram._post") as post:
        post.return_value = True
        assert notify_stage_result("nuclei_default", result, _cfg()) is True
        msg = post.call_args[0][2]
        # all severities should appear as 0
        assert "critical: <code>0</code>" in msg
        assert "high:     <code>0</code>" in msg


# ----------------------------------------------------------------------
# content_discovery — URL + JS count
# ----------------------------------------------------------------------
def test_content_discovery_message_includes_js_count():
    result = {"status": "success", "count": 250, "extra": {"js_urls": 12}}
    with patch("modules.telegram._post") as post:
        post.return_value = True
        assert notify_stage_result("content_discovery", result, _cfg()) is True
        msg = post.call_args[0][2]
        assert "content_discovery" in msg
        assert "<code>250</code>" in msg
        assert "<code>12</code>" in msg
        assert "JS" in msg


def test_content_discovery_with_zero_js_urls():
    result = {"status": "success", "count": 5, "extra": {"js_urls": 0}}
    with patch("modules.telegram._post") as post:
        post.return_value = True
        notify_stage_result("content_discovery", result, _cfg())
        msg = post.call_args[0][2]
        assert "<code>0</code>" in msg


# ----------------------------------------------------------------------
# generic stage — fallback format
# ----------------------------------------------------------------------
def test_generic_stage_message():
    result = {"status": "success", "count": 42, "extra": {}}
    with patch("modules.telegram._post") as post:
        post.return_value = True
        assert notify_stage_result("arjun", result, _cfg()) is True
        msg = post.call_args[0][2]
        assert "arjun" in msg
        assert "<code>42</code>" in msg


# ----------------------------------------------------------------------
# propagation of _post's return value
# ----------------------------------------------------------------------
def test_returns_post_return_value():
    result = {"status": "success", "count": 1, "extra": {}}
    with patch("modules.telegram._post") as post:
        post.return_value = False  # simulate network failure
        assert notify_stage_result("subdomain", result, _cfg()) is False