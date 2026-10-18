"""Canonical, broker-neutral event contract for the scoring pipeline."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class NormalizedEvent(BaseModel):
    """Validated event shape shared by broker adapters and the scoring API.

    A broker-specific adapter maps authorized source fields into this model.
    This contract deliberately excludes synthetic evaluation labels and
    rejects undeclared fields so source-specific payloads cannot leak through.
    """

    event_id: str
    account_id: str
    timestamp: str
    event_type: Literal[
        "LOGIN", "LOGOUT", "VIEW_STOCK", "ORDER", "CANCEL_ORDER",
        "API_REQUEST", "TOKEN_REFRESH", "PASSWORD_CHANGE", "DEVICE_CHANGE",
    ]
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    session_id: str
    success: Optional[bool] = None
    auth_method: Optional[Literal["password", "token", "mfa"]] = None
    symbol: Optional[str] = None
    order_type: Optional[Literal["buy", "sell"]] = None
    quantity: Optional[int] = Field(default=None, gt=0)
    price: Optional[float] = Field(default=None, gt=0, allow_inf_nan=False)
    order_value: Optional[float] = Field(default=None, gt=0, allow_inf_nan=False)
    time_since_order_ms: Optional[float] = Field(default=None, ge=0, allow_inf_nan=False)
    client_id: Optional[str] = None
    original_order_id: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[Literal["GET", "POST", "PUT", "DELETE"]] = None
    status_code: Optional[int] = Field(default=None, ge=100, le=599)
    token_type: Optional[Literal["access", "refresh"]] = None
    initiated_by: Optional[Literal["user", "admin_reset"]] = None
    previous_device_id: Optional[str] = None
    new_device_id: Optional[str] = None

    model_config = {
        "extra": "forbid",
        "json_schema_extra": {
            "example": {
                "event_id": "evt-demo-1",
                "account_id": "ACC0001",
                "timestamp": "2026-09-18T10:15:00+00:00",
                "event_type": "ORDER",
                "device_id": "device-abc123",
                "ip_address": "10.0.0.5",
                "session_id": "sess-1",
                "order_value": 50000.0,
            }
        },
    }

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_iso8601(cls, value: str) -> str:
        try:
            parsed_timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("timestamp must be an ISO 8601 datetime with timezone") from error
        if parsed_timestamp.tzinfo is None or parsed_timestamp.utcoffset() is None:
            raise ValueError("timestamp must include a timezone offset")
        return value

    @model_validator(mode="before")
    @classmethod
    def reject_ground_truth(cls, value: Any) -> Any:
        if isinstance(value, dict) and {"is_attack", "attack_type"}.intersection(value):
            raise ValueError("ground-truth fields are not part of the normalized event contract")
        return value
