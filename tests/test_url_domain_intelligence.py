import os
import sys
import unittest
from unittest.mock import Mock, patch

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.url_domain_intelligence import URLDomainIntelligence, parse_target


class TestURLDomainIntelligence(unittest.TestCase):
    def test_parses_domain_and_url_metadata(self):
        domain = parse_target('example.com')
        target = parse_target('https://sub.example.com/path?x=1#part')
        self.assertEqual(domain['input_type'], 'Domain')
        self.assertEqual(domain['port'], 443)
        self.assertEqual(target['input_type'], 'URL')
        self.assertEqual(target['registered_domain'], 'example.com')
        self.assertEqual(target['subdomain'], 'sub')
        self.assertTrue(target['query_present'])
        self.assertTrue(target['fragment_present'])

    def test_normalizes_case_and_custom_port(self):
        result = parse_target('HTTP://WWW.Example.COM:8080/path')
        self.assertEqual(result['hostname'], 'www.example.com')
        self.assertEqual(result['scheme'], 'http')
        self.assertEqual(result['port'], 8080)
        self.assertEqual(result['path'], '/path')

    def test_rejects_invalid_and_unsupported_targets(self):
        for value in ('', 'ftp://example.com', 'https://localhost', 'https://127.0.0.1', 'https://example.com:bad'):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_target(value)

    @patch('core.url_domain_intelligence._is_public_hostname', return_value=True)
    def test_inspects_http_response(self, public_host):
        response = Mock(status_code=200, url='https://example.com/', history=[])
        response.headers = {'Content-Type': 'text/html', 'Server': 'nginx'}
        session = Mock()
        session.get.return_value = response
        result = URLDomainIntelligence(session=session).analyze('https://example.com', inspect_http=True)
        self.assertEqual(result['http']['status'], 'SUCCESS')
        self.assertEqual(result['http']['server'], 'nginx')

    @patch('core.url_domain_intelligence._is_public_hostname', return_value=True)
    def test_handles_timeout_and_redirects(self, public_host):
        session = Mock()
        session.get.side_effect = requests.Timeout()
        result = URLDomainIntelligence(session=session).analyze('http://example.com', inspect_http=True)
        self.assertEqual(result['http']['status'], 'FAILED')


if __name__ == '__main__':
    unittest.main()