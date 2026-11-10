"""Bounded syntax codec for the pinned FreeTurn v1 share format, not enrollment."""

import base64
import json

from .installer import _unique_object
from .store import ValidationError

PREFIX = "freeturn://"
MAX_RAW = 65536
MAX_STRING = 49152
STRINGS = ("provider", "peer", "transport", "mode", "obf", "key", "cid", "listen", "dns", "dnss", "name", "vk", "wg")
INTEGERS = ("v", "timing", "n", "spc")
BOOLEANS = ("bond", "mcap")
KCP_INTEGERS = ("nodelay", "interval", "resend", "nc", "sndwnd", "rcvwnd", "mtu")


def validate(value):
    allowed = set(STRINGS + INTEGERS + BOOLEANS) | {"kcp"}
    if not isinstance(value, dict) or not {"v", "provider", "peer"} <= value.keys() or value.keys() - allowed:
        raise ValidationError("Unsupported FreeTurn profile fields")
    for key, item in value.items():
        if key in STRINGS and (not isinstance(item, str) or len(item) > MAX_STRING):
            raise ValidationError("Invalid FreeTurn string field")
        if key in INTEGERS and (type(item) is not int or not -(2**31) <= item < 2**31):
            raise ValidationError("Invalid FreeTurn integer field")
        if key in BOOLEANS and type(item) is not bool:
            raise ValidationError("Invalid FreeTurn boolean field")
    if value["v"] != 1 or not value["provider"] or not value["peer"]:
        raise ValidationError("Unsupported or incomplete FreeTurn profile")
    if "kcp" in value:
        kcp = value["kcp"]
        if not isinstance(kcp, dict) or set(kcp) != set(KCP_INTEGERS) | {"acknodelay"}:
            raise ValidationError("Complete KCP settings required for consistent client defaults")
        if (any(type(kcp[key]) is not int or not -(2**31) <= kcp[key] < 2**31 for key in KCP_INTEGERS)
                or type(kcp["acknodelay"]) is not bool):
            raise ValidationError("Invalid KCP field types")
    try:
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    except (ValueError, UnicodeError):
        raise ValidationError("Invalid FreeTurn text encoding") from None
    if len(raw) > MAX_RAW:
        raise ValidationError("FreeTurn profile exceeds size limit")
    return {key: dict(item) if key == "kcp" else item for key, item in value.items()}


def encode(value):
    value = validate(value)
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    return PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode(link):
    if not isinstance(link, str) or len(link) > (MAX_RAW + 2) // 3 * 4 + len(PREFIX):
        raise ValidationError("FreeTurn link exceeds size limit")
    if not link.startswith(PREFIX):
        raise ValidationError("Unsupported share link scheme")
    payload = link[len(PREFIX):]
    try:
        raw = base64.b64decode(payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True)
        if len(raw) > MAX_RAW or base64.urlsafe_b64encode(raw).decode().rstrip("=") != payload:
            raise ValueError()
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise ValidationError("Invalid FreeTurn link encoding or JSON") from None
    return validate(value)


def json_schema():
    integer = {"type": "integer", "minimum": -(2**31), "maximum": 2**31 - 1}
    properties = {key: {"type": "string", "maxLength": MAX_STRING} for key in STRINGS}
    properties.update({key: dict(integer) for key in INTEGERS})
    properties.update({key: {"type": "boolean"} for key in BOOLEANS})
    properties["v"] = {"type": "integer", "const": 1}
    for key in ("provider", "peer"):
        properties[key]["minLength"] = 1
    kcp = {key: dict(integer) for key in KCP_INTEGERS}
    kcp["acknodelay"] = {"type": "boolean"}
    properties["kcp"] = {"type": "object", "additionalProperties": False, "required": list(kcp), "properties": kcp}
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "title": "FreeTurn v1 share payload supported by FTM",
            "$comment": "Syntax contract only. Encoded JSON is limited to 65536 UTF-8 bytes. Not a managed subscription or runtime-config validator.",
            "type": "object", "additionalProperties": False, "required": ["v", "provider", "peer"], "properties": properties}
