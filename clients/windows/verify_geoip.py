"""Targeted checks for country data integrity and unintended DIRECT ranges."""
import gzip
import hashlib
import unittest
from unittest.mock import patch

from routing_geoip import compile_geoip


def fixture(text):
    raw = text.encode('utf-8')
    data = gzip.compress(raw, mtime=0)
    return data, dict(sha256=hashlib.sha256(data).hexdigest(),
                     uncompressedSHA256=hashlib.sha256(raw).hexdigest(), records=len(text.splitlines()))


class GeoIPBoundaryChecks(unittest.TestCase):
    def test_only_ru_ipv4_and_exact_range_boundaries(self):
        data, meta = fixture('1.1.1.0,1.1.1.255,AU\n8.8.8.0,8.8.8.255,US\n77.88.55.1,77.88.55.6,RU\n2001:db8::,2001:db8::ff,RU\n')
        self.assertEqual(compile_geoip(data, meta), ['77.88.55.1/32', '77.88.55.2/31', '77.88.55.4/31', '77.88.55.6/32'])

    def test_hash_count_and_decompression_bounds(self):
        data, meta = fixture('77.88.55.0,77.88.55.255,RU\n')
        for changed, values in [(data + b'x', meta), (data, dict(meta, uncompressedSHA256='0' * 64)), (data, dict(meta, records=2))]:
            with self.assertRaisesRegex(ValueError, '^GEOIP_SOURCE_INVALID$'):
                compile_geoip(changed, values)
        with patch('routing_geoip.MAX_RAW', 8), self.assertRaises(ValueError):
            compile_geoip(data, meta)

    def test_format_order_overlap_and_special_ranges_refused(self):
        for text in [
            '77.88.55.8,77.88.55.1,RU\n', '77.88.55.0,::1,RU\n',
            '77.88.55.0,77.88.55.255,RU\n77.88.55.128,77.88.55.255,RU\n',
            '8.8.8.0,8.8.8.255,US\n1.1.1.0,1.1.1.255,AU\n',
            '77.88.55.0,77.88.55.255,ru\n', '77.88.55.0,77.88.55.255,RU,extra\n',
            '10.0.0.0,10.255.255.255,RU\n', '169.254.169.254,169.254.169.254,RU\n',
            '0.0.0.0,255.255.255.255,RU\n',
        ]:
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, '^GEOIP_SOURCE_INVALID$'):
                compile_geoip(*fixture(text))


if __name__ == '__main__':
    unittest.main()
