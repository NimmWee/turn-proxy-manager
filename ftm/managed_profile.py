"""Managed v1 contract and client-local share assembly. No system/network changes."""

import ipaddress
import json
import re
import uuid
from urllib.parse import urlsplit

from .profile_codec import encode, validate as validate_share, json_schema as share_schema
from .store import ValidationError, valid_key

WG_FIELDS = {"client_public_key", "addresses", "server_public_key", "preshared_key", "allowed_ips", "dns", "mtu",
             "local_endpoint", "persistent_keepalive", "ipv6_policy"}
FT_FIELDS = {"v", "provider", "peer", "transport", "mode", "obf", "key", "n", "spc", "cid", "dns", "mcap", "vk"}
MG_FIELDS = {"origin", "api_path", "internal_api_ip", "tls_server_name", "refresh_seconds"}
FIELDS = {"schema_version", "format", "device_id", "revision", "name", "platform", "wireguard", "freeturn", "management"}


def validate_manifest(value, *, expected_public_key=None, expected_origin=None):
    try:
        if not isinstance(value, dict) or set(value) != FIELDS or type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["format"] != "ftm-managed":
            raise ValueError()
        if str(uuid.UUID(value["device_id"])) != value["device_id"] or type(value["revision"]) is not int or value["revision"] < 1:
            raise ValueError()
        if (not isinstance(value["name"], str) or not 1 <= len(value["name"]) <= 128 or any(ord(c) < 32 for c in value["name"])
                or value["platform"] not in ("android", "windows", "other")):
            raise ValueError()
        wg, ft, management = value["wireguard"], value["freeturn"], value["management"]
        if not all(isinstance(item, dict) for item in (wg, ft, management)) or set(wg) != WG_FIELDS or set(ft) != FT_FIELDS or set(management) != MG_FIELDS:
            raise ValueError()
        if not all(valid_key(wg[key]) for key in ("client_public_key", "server_public_key", "preshared_key")):
            raise ValueError()
        if expected_public_key is not None and wg["client_public_key"] != expected_public_key:
            raise ValueError()
        if not isinstance(wg["addresses"], list) or not 1 <= len(wg["addresses"]) <= 2:
            raise ValueError()
        for address in wg["addresses"]:
            interface = ipaddress.ip_interface(address)
            if str(interface) != address or interface.network.prefixlen != interface.max_prefixlen:
                raise ValueError()
        if wg["allowed_ips"] != ["0.0.0.0/0", "::/0"] or wg["local_endpoint"] != "127.0.0.1:9000" or wg["ipv6_policy"] != "block":
            raise ValueError()
        if not isinstance(wg["dns"], list) or not 1 <= len(wg["dns"]) <= 4:
            raise ValueError()
        for address in wg["dns"]:
            if str(ipaddress.ip_address(address)) != address:
                raise ValueError()
        if type(wg["mtu"]) is not int or not 576 <= wg["mtu"] <= 1420 or type(wg["persistent_keepalive"]) is not int or not 1 <= wg["persistent_keepalive"] <= 120:
            raise ValueError()
        validate_share(ft)
        if (ft["provider"] != "vk" or ft["transport"] != "tcp" or ft["mode"] != "udp" or ft["obf"] != "rtpopus3"
                or not re.fullmatch(r"[a-f0-9]{64}", ft["key"]) or not re.fullmatch(r"[a-f0-9]{32}", ft["cid"])):
            raise ValueError()
        room = urlsplit(ft["vk"])
        if room.scheme != "https" or room.netloc not in ("vk.com", "vk.ru") or not room.path.startswith("/call/join/") or any(c.isspace() for c in ft["vk"]):
            raise ValueError()
        origin = urlsplit(management["origin"])
        if (origin.scheme != "https" or not origin.hostname or origin.username or origin.password or origin.path or origin.query or origin.fragment
                or origin.port not in (None, 443) or management["tls_server_name"] != origin.hostname or management["api_path"] != "/api/client/v1/"
                or type(management["refresh_seconds"]) is not int or management["refresh_seconds"] != 1800):
            raise ValueError()
        peer_host, peer_port = ft["peer"].rsplit(":", 1)
        if peer_host != origin.hostname or not peer_port.isdecimal() or not 1 <= int(peer_port) <= 65535:
            raise ValueError()
        if not 1 <= ft["n"] <= 64 or not 1 <= ft["spc"] <= 64:
            raise ValueError()
        ipaddress.IPv4Address(management["internal_api_ip"])
        if expected_origin is not None and management["origin"] != expected_origin:
            raise ValueError()
        # Bound the whole contract before a client persists anything.
        if len(json.dumps(value).encode()) > 65536:
            raise ValueError()
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise ValidationError("Managed configuration rejected; private values withheld") from None
    return value


def to_share(value, private_key, *, expected_public_key, expected_origin):
    value = validate_manifest(value, expected_public_key=expected_public_key, expected_origin=expected_origin)
    if not valid_key(private_key):
        raise ValidationError("Invalid local private key")
    wg = value["wireguard"]
    text = ("[Interface]\nPrivateKey = " + private_key + "\nAddress = " + ", ".join(wg["addresses"]) +
            "\nDNS = " + ", ".join(wg["dns"]) + "\nMTU = " + str(wg["mtu"]) +
            "\n\n[Peer]\nPublicKey = " + wg["server_public_key"] + "\nPresharedKey = " + wg["preshared_key"] +
            "\nAllowedIPs = " + ", ".join(wg["allowed_ips"]) + "\nEndpoint = " + wg["local_endpoint"] +
            "\nPersistentKeepalive = " + str(wg["persistent_keepalive"]) + "\n")
    return encode({**value["freeturn"], "name": value["name"], "wg": text})


def json_schema():
    key = {"type": "string", "pattern": "^[A-Za-z0-9+/]{43}=$"}
    string = {"type": "string", "maxLength": 49152}
    def obj(properties):
        return {"type": "object", "additionalProperties": False, "required": list(properties), "properties": properties}
    wg = obj({"client_public_key": key, "server_public_key": key, "preshared_key": key,
              "addresses": {"type": "array", "minItems": 1, "maxItems": 2, "items": string},
              "allowed_ips": {"const": ["0.0.0.0/0", "::/0"]}, "dns": {"type": "array", "minItems": 1, "maxItems": 4, "items": string},
              "mtu": {"type": "integer", "minimum": 576, "maximum": 1420}, "local_endpoint": {"const": "127.0.0.1:9000"},
              "persistent_keepalive": {"type": "integer", "minimum": 1, "maximum": 120}, "ipv6_policy": {"const": "block"}})
    freeturn = share_schema()
    ft = obj({field: freeturn["properties"][field] for field in sorted(FT_FIELDS)})
    for field, value in (("provider", "vk"), ("transport", "tcp"), ("mode", "udp"), ("obf", "rtpopus3")):
        ft["properties"][field] = {"const": value}
    for field, length in (("key", 64), ("cid", 32)):
        ft["properties"][field] = {"type": "string", "pattern": "^[a-f0-9]{" + str(length) + "}$"}
    for field in ("n", "spc"):
        ft["properties"][field] = {"type": "integer", "minimum": 1, "maximum": 64}
    management = obj({"origin": string, "api_path": {"const": "/api/client/v1/"}, "internal_api_ip": {"type": "string", "format": "ipv4"},
                      "tls_server_name": string, "refresh_seconds": {"const": 1800}})
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "title": "FTM managed device v1 (no private key)",
            **obj({"schema_version": {"const": 1}, "format": {"const": "ftm-managed"}, "device_id": {"type": "string", "format": "uuid"},
                   "revision": {"type": "integer", "minimum": 1}, "name": {"type": "string", "minLength": 1, "maxLength": 128},
                   "platform": {"enum": ["android", "windows", "other"]}, "wireguard": wg, "freeturn": ft, "management": management})}
