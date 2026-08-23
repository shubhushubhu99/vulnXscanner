import os
import sys
import unittest
from unittest.mock import Mock

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.ip_geolocation import IPGeolocation, NOT_AVAILABLE, parse_ip


class TestIPValidation(unittest.TestCase):
    def test_parses_ipv4_and_ipv6(self):
        self.assertEqual(parse_ip('8.8.8.8').version, 4)
        self.assertEqual(parse_ip('2001:4860:4860::8888').version, 6)

    def test_rejects_invalid_input(self):
        for value in ('', 'https://8.8.8.8', 'not-an-ip'):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_ip(value)

    def test_private_ip_does_not_call_service(self):
        session = Mock()
        result = IPGeolocation(session=session).lookup('192.168.1.1')
        self.assertEqual(result['status'], 'PRIVATE/RESERVED')
        session.get.assert_not_called()


class TestIPGeolocation(unittest.TestCase):
    def test_normalizes_public_response(self):
        response = Mock()
        response.json.return_value = {
            'success': True,
            'ip': '8.8.8.8',
            'country': 'United States',
            'country_code': 'US',
            'region': 'California',
            'city': 'Mountain View',
            'latitude': 37.4056,
            'longitude': -122.0775,
            'connection': {'isp': 'Google', 'org': 'Google LLC', 'asn': 'AS15169'},
            'timezone': {'id': 'America/Los_Angeles'},
            'security': {'hosting': True},
        }
        response.raise_for_status.return_value = None
        session = Mock()
        session.get.return_value = response

        result = IPGeolocation(session=session).lookup('8.8.8.8')

        self.assertEqual(result['status'], 'SUCCESS')
        self.assertEqual(result['country_code'], 'US')
        self.assertEqual(result['asn'], 'AS15169')
        self.assertEqual(result['network_type'], 'Hosting / CDN / Datacenter')
        self.assertTrue(result['approximate'])

    def test_handles_timeout(self):
        session = Mock()
        session.get.side_effect = requests.Timeout()
        result = IPGeolocation(session=session).lookup('1.1.1.1')
        self.assertEqual(result['status'], 'ERROR')
        self.assertIn('timed out', result['message'])

    def test_handles_missing_fields(self):
        response = Mock()
        response.json.return_value = {
            'success': True,
            'ip': '8.8.8.8',
            'country': 'United States',
            'country_code': 'US',
        }
        response.raise_for_status.return_value = None
        session = Mock()
        session.get.return_value = response
        result = IPGeolocation(session=session).lookup('8.8.8.8')
        self.assertEqual(result['status'], 'PARTIAL')
        self.assertEqual(result['city'], NOT_AVAILABLE)

    def test_rejects_provider_ip_mismatch(self):
        response = Mock()
        response.json.return_value = {
            'success': True,
            'ip': '1.1.1.1',
            'country': 'United States',
            'country_code': 'US',
        }
        response.raise_for_status.return_value = None
        session = Mock()
        session.get.return_value = response

        result = IPGeolocation(session=session).lookup('8.8.8.8')

        self.assertEqual(result['status'], 'FAILED')
        self.assertIn('different IP', result['message'])

    def test_rejects_unusable_success_response(self):
        response = Mock()
        response.json.return_value = {'success': True, 'ip': '8.8.8.8'}
        response.raise_for_status.return_value = None
        session = Mock()
        session.get.return_value = response

        result = IPGeolocation(session=session).lookup('8.8.8.8')

        self.assertEqual(result['status'], 'FAILED')
    
    def test_marks_invalid_coordinates_partial(self):
        response = Mock()
        response.json.return_value = {
            'success': True,
            'ip': '8.8.8.8',
            'country': 'United States',
            'country_code': 'US',
            'latitude': 'invalid',
            'longitude': -122.0,
        }
        response.raise_for_status.return_value = None
        session = Mock()
        session.get.return_value = response

        result = IPGeolocation(session=session).lookup('8.8.8.8')

        self.assertEqual(result['status'], 'PARTIAL')
        self.assertEqual(result['latitude'], NOT_AVAILABLE)


if __name__ == '__main__':
    unittest.main()