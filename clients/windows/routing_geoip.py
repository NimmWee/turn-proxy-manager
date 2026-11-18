"""Pure compiler for the pinned DB-IP Lite CSV; no network or file writes."""
import csv
import gzip
import hashlib
import io
import ipaddress
import re

MAX_COMPRESSED = 32 * 1024 * 1024
MAX_RAW = 64 * 1024 * 1024
FORBIDDEN = tuple(map(ipaddress.ip_network, (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
    '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
    '224.0.0.0/4', '240.0.0.0/4', '168.63.129.16/32',
)))


def compile_geoip(payload, metadata):
    """Return canonical RU IPv4 prefixes, rejecting untrusted/inconsistent data."""
    try:
        if len(payload) > MAX_COMPRESSED or hashlib.sha256(payload).hexdigest() != metadata['sha256']:
            raise ValueError()
        with gzip.GzipFile(fileobj=io.BytesIO(payload)) as source:
            raw = source.read(MAX_RAW + 1)
        if len(raw) > MAX_RAW or hashlib.sha256(raw).hexdigest() != metadata['uncompressedSHA256']:
            raise ValueError()
        last = {4: -1, 6: -1}
        prefixes = []
        count = 0
        for row in csv.reader(io.StringIO(raw.decode('utf-8')), strict=True):
            if len(row) != 3 or not re.fullmatch('[A-Z]{2}', row[2]):
                raise ValueError()
            first, end = map(ipaddress.ip_address, row[:2])
            if (first.version != end.version or int(first) > int(end)
                    or int(first) <= last[first.version] or '%' in row[0] or '%' in row[1]):
                raise ValueError()
            last[first.version] = int(end)
            count += 1
            if row[2] != 'RU' or first.version != 4:
                continue
            for network in ipaddress.summarize_address_range(first, end):
                if any(network.overlaps(reserved) for reserved in FORBIDDEN):
                    raise ValueError()
                prefixes.append(network)
        if count != metadata['records'] or not prefixes:
            raise ValueError()
        return [str(network) for network in ipaddress.collapse_addresses(prefixes)]
    except (KeyError, ValueError, TypeError, OSError, EOFError, csv.Error):
        raise ValueError('GEOIP_SOURCE_INVALID') from None
