import os
import socket
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.osint_scan import resolve_domain, run_osint_scan


class TestOSINTScan(unittest.TestCase):
    @patch('core.osint_scan.socket.getaddrinfo')
    def test_resolves_and_selects_public_ip(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0)),
        ]
        result = resolve_domain('example.com')
        self.assertEqual(result['status'], 'SUCCESS')
        self.assertEqual(result['ip'], '93.184.216.34')

    @patch('core.osint_scan.resolve_domain')
    def test_partial_failure_keeps_other_modules(self, resolve):
        resolve.return_value = {
            'status': 'SUCCESS', 'ip': '93.184.216.34',
            'version': 'IPv4', 'addresses': ['93.184.216.34']
        }
        whois = Mock()
        whois.lookup.return_value = {'status': 'SUCCESS', 'domain': 'example.com'}
        geo = Mock()
        geo.lookup.side_effect = RuntimeError('service down')

        result = run_osint_scan('WWW.Example.COM', whois, geo)

        self.assertEqual(result['target'], 'example.com')
        self.assertEqual(result['whois']['status'], 'SUCCESS')
        self.assertEqual(result['ip_geolocation']['status'], 'ERROR')
        geo.lookup.assert_called_once_with('93.184.216.34')

    @patch('core.osint_scan.resolve_domain')
    def test_dns_failure_does_not_block_whois(self, resolve):
        resolve.return_value = {
            'status': 'ERROR', 'ip': None, 'version': None,
            'addresses': [], 'message': 'DNS failed'
        }
        whois = Mock()
        whois.lookup.return_value = {'status': 'SUCCESS', 'domain': 'example.com'}
        geo = Mock()

        result = run_osint_scan('example.com', whois, geo)

        self.assertEqual(result['whois']['status'], 'SUCCESS')
        self.assertEqual(result['ip_geolocation']['status'], 'NOT AVAILABLE')
        geo.lookup.assert_not_called()

    @patch('core.osint_scan.resolve_domain')
    def test_whois_failure_does_not_block_geolocation(self, resolve):
        resolve.return_value = {
            'status': 'SUCCESS', 'ip': '93.184.216.34',
            'version': 'IPv4', 'addresses': ['93.184.216.34']
        }
        whois = Mock()
        whois.lookup.side_effect = RuntimeError('WHOIS unavailable')
        geo = Mock()
        geo.lookup.return_value = {'status': 'SUCCESS', 'ip': '93.184.216.34'}

        result = run_osint_scan('example.com', whois, geo)

        self.assertEqual(result['whois']['status'], 'ERROR')
        self.assertEqual(result['ip_geolocation']['status'], 'SUCCESS')
        geo.lookup.assert_called_once_with('93.184.216.34')

    @patch('core.osint_scan.resolve_domain')
    def test_technology_detection_is_part_of_unified_scan(self, resolve):
        resolve.return_value = {
            'status': 'SUCCESS', 'ip': '93.184.216.34',
            'version': 'IPv4', 'addresses': ['93.184.216.34']
        }
        whois = Mock()
        whois.lookup.return_value = {'status': 'SUCCESS'}
        geo = Mock()
        geo.lookup.return_value = {'status': 'SUCCESS'}
        technology = Mock()
        technology.detect.return_value = {'status': 'SUCCESS', 'technologies': []}

        result = run_osint_scan('example.com', whois, geo, technology)

        self.assertEqual(result['technology_detection']['status'], 'SUCCESS')
        technology.detect.assert_called_once_with('example.com')

    @patch('core.osint_scan.resolve_domain')
    def test_technology_failure_does_not_block_existing_modules(self, resolve):
        resolve.return_value = {
            'status': 'SUCCESS', 'ip': '93.184.216.34',
            'version': 'IPv4', 'addresses': ['93.184.216.34']
        }
        whois = Mock()
        whois.lookup.return_value = {'status': 'SUCCESS'}
        geo = Mock()
        geo.lookup.return_value = {'status': 'SUCCESS'}
        technology = Mock()
        technology.detect.side_effect = RuntimeError('detector unavailable')

        result = run_osint_scan('example.com', whois, geo, technology)

        self.assertEqual(result['whois']['status'], 'SUCCESS')
        self.assertEqual(result['ip_geolocation']['status'], 'SUCCESS')
        self.assertEqual(result['technology_detection']['status'], 'FAILED')

    @patch('core.osint_scan.resolve_domain')
    def test_url_input_is_normalized_before_existing_modules(self, resolve):
        resolve.return_value = {
            'status': 'SUCCESS', 'ip': '93.184.216.34',
            'version': 'IPv4', 'addresses': ['93.184.216.34']
        }
        whois = Mock()
        whois.lookup.return_value = {'status': 'SUCCESS'}
        geo = Mock()
        geo.lookup.return_value = {'status': 'SUCCESS'}
        technology = Mock()
        technology.detect.return_value = {'status': 'SUCCESS'}

        result = run_osint_scan('https://www.example.com/login', whois, geo, technology)

        self.assertEqual(result['target'], 'example.com')
        self.assertEqual(result['url_domain_intelligence']['input_type'], 'URL')
        whois.lookup.assert_called_once_with('example.com')
        resolve.assert_called_once_with('example.com')
        technology.detect.assert_called_once_with('example.com')

if __name__ == '__main__':
    unittest.main()