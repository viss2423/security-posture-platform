from app.errors import _error_payload
from app.request_context import request_id_ctx


def test_error_payload_marks_retryable_for_server_error():
    payload = _error_payload(message="boom", status_code=503)
    assert payload["error"]["retryable"] is True


def test_error_payload_marks_non_retryable_for_bad_request():
    payload = _error_payload(message="bad", status_code=400)
    assert payload["error"]["retryable"] is False


def test_error_payload_includes_request_id_when_present():
    token = request_id_ctx.set("req-test-123")
    try:
        payload = _error_payload(message="boom", status_code=500)
    finally:
        request_id_ctx.reset(token)
    assert payload["error"]["request_id"] == "req-test-123"
