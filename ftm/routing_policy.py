"""Root-owned routing publication. API uses typed IPC, never opens SQLite."""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re

from .store import Conflict, ValidationError

PRESETS = ("russianDirect", "lanDirect", "youtubeVPN", "pushVPN", "connectivityDirect", "blockBitTorrent", "splitDNS")
CAPABILITY = "routing-bundle-v1"

def validate_policy(value):
    if not isinstance(value, dict) or set(value) != {"presets", "rules", "directDNS"}:
        raise ValidationError("Invalid routing fields")
    presets, rules, dns = value["presets"], value["rules"], value["directDNS"]
    if not isinstance(presets, dict) or set(presets) != set(PRESETS) or any(type(v) is not bool for v in presets.values()):
        raise ValidationError("Invalid routing presets")
    if not isinstance(rules, list) or len(rules) > 128:
        raise ValidationError("Too many routing domains")
    seen = set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {"domain", "action", "subdomains"} or rule["action"] not in ("direct", "vpn", "block") or type(rule["subdomains"]) is not bool:
            raise ValidationError("Invalid routing rule")
        host = rule["domain"]
        if not isinstance(host, str) or len(host) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host) or "." not in host or any(not 1 <= len(s) <= 63 or s.startswith("-") or s.endswith("-") for s in host.split(".")) or host in seen:
            raise ValidationError("Use unique lower-case ASCII/IDNA domains")
        if host.replace(".", "").isdigit():
            raise ValidationError("IP addresses are not domain rules")
        seen.add(host)
    import ipaddress
    if not isinstance(dns, list) or not 1 <= len(dns) <= 4 or any(not isinstance(v,str) for v in dns) or len(set(dns)) != len(dns):
        raise ValidationError("Invalid routing DNS")
    try:
        if any(not isinstance(s, str) or str(ipaddress.IPv4Address(s)) != s or not ipaddress.IPv4Address(s).is_global for s in dns):
            raise ValueError()
    except (ValueError, TypeError):
        raise ValidationError("Public IPv4 DNS required") from None
    if len(json.dumps(value).encode()) > 12000:
        raise ValidationError("Routing policy too large")
    return value

class RoutingPublication:
    def __init__(self, store): self.store = store
    @staticmethod
    def _read(db):
        row = db.execute("SELECT revision,policy,catalog FROM routing_publication WHERE id=1").fetchone()
        return {"v": 1, "revision": row[0], "policy": json.loads(row[1]), "catalog": json.loads(row[2]) if row[2] else None} if row else {"v": 1, "revision": 0, "policy": {"presets": dict.fromkeys(PRESETS, True), "rules": [], "directDNS": ["77.88.8.8", "77.88.8.1"]}, "catalog": None}
    def read(self):
        with self.store.connect() as db: return self._read(db)
    def publish(self, expected_revision, policy, *, catalog=None):
        validate_policy(policy)
        if type(expected_revision) is not int or not 0 <= expected_revision < 9007199254740991:
            raise ValidationError("Invalid routing revision")
        with self.store.transaction() as db:
            previous = self._read(db)
            if expected_revision != previous["revision"]: raise Conflict("Routing publication changed; reload before saving")
            revision = expected_revision + 1
            data = previous["catalog"] if catalog is None else catalog
            db.execute("INSERT OR REPLACE INTO routing_publication VALUES(1,?,?,?)", (revision, json.dumps(policy, separators=(",", ":")), json.dumps(data, separators=(",", ":")) if data else None))
            self.store._audit(db, "routing.publish", "routing", str(revision))
            return {"revision": revision}

def import_catalog(store, path, expected_sha256):
    # Explicit root trust decision. Not exposed to HTTP/IPC; source data must be
    # built by the pinned preparer first. No URLs, shell, service or VPN changes.
    if Path(path).stat().st_size > 1024*1024: raise ValidationError("Catalogue too large")
    raw = Path(path).read_bytes()
    if len(raw) > 1024*1024 or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256) or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValidationError("Catalogue hash rejected")
    from .installer import _unique_object
    value = json.loads(raw, object_pairs_hook=_unique_object)
    if set(value) != {"v", "ru", "youtube", "push", "connectivity", "ruPrefixes", "sources", "countryAddressMeaning", "geoIP"} or value["v"] != 1 or value["geoIP"].get("license") != "CC-BY-4.0" or value["geoIP"].get("country") != "RU":
        raise ValidationError("Catalogue format rejected")
    packed = base64.b64encode(gzip.compress(raw, mtime=0)).decode()
    if len(packed) > 170000: raise ValidationError("Catalogue too large")
    publication = RoutingPublication(store); current = publication.read()
    return publication.publish(current["revision"], current["policy"], catalog={"sha256": expected_sha256, "gzip": packed})

def main():
    parser = argparse.ArgumentParser(description="Offline root routing catalogue publication")
    parser.add_argument("--db", required=True); parser.add_argument("--catalog", required=True); parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0: parser.error("root on Linux required")
    from .store import Store
    store = Store(args.db); store.initialize()
    print(json.dumps(import_catalog(store, args.catalog, args.sha256)))
if __name__ == "__main__": main()
