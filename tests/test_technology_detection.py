import os
import socket
import sys
import unittest
from unittest.mock import Mock, patch

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.technology_detection import TechnologyDetection


class TestTechnologyDetection(unittest.TestCase):
    def response(self, headers=None, body=''):
        response = Mock()
        response.status_code = 200
        response.headers = headers or {}
        response.text = body
        return response

    @patch('core.technology_detection._public_host', return_value=True)
    def test_detects_headers_and_html_fingerprints(self, public_host):
        session = Mock()
        session.get.return_value = self.response(
            {'Server': 'nginx', 'CF-Ray': 'abc', 'Content-Security-Policy': 'default-src self'},
            '<script src="/jquery.js"></script><div id="wp-content"></div>',
        )
        result = TechnologyDetection(session=session).detect('example.com')
        names = {item['name'] for item in result['technologies']}
        self.assertEqual(result['status'], 'SUCCESS')
        self.assertEqual(names, {'nginx', 'Cloudflare', 'jQuery', 'WordPress'})
        self.assertEqual(result['security_headers'], ['Content-Security-Policy'])
        public_host.assert_called_once_with('example.com')

    @patch('core.technology_detection._public_host', return_value=True)
    def test_returns_no_fake_technologies(self, public_host):
        session = Mock()
        session.get.return_value = self.response(body='<html><body>Hello</body></html>')
        result = TechnologyDetection(session=session).detect('example.com')
        self.assertEqual(result['status'], 'SUCCESS')
        self.assertEqual(result['technologies'], [])
        self.assertEqual(result['security_headers'], [])
        self.assertIn('No publicly detectable', result['message'])

    def test_rejects_invalid_domain(self):
        with self.assertRaises(ValueError):
            TechnologyDetection().detect('https://example.com')

    @patch('core.technology_detection._public_host', return_value=True)
    def test_handles_timeout(self, public_host):
        session = Mock()
        session.get.side_effect = requests.Timeout()
        result = TechnologyDetection(session=session).detect('example.com')
        self.assertEqual(result['status'], 'FAILED')

    @patch('core.technology_detection._public_host', return_value=True)
    def test_handles_connection_failure(self, public_host):
        session = Mock()
        session.get.side_effect = requests.ConnectionError()
        result = TechnologyDetection(session=session).detect('example.com')
        self.assertEqual(result['status'], 'FAILED')

    @patch('core.technology_detection._public_host', return_value=True)
    def test_handles_malformed_response(self, public_host):
        response = Mock()
        response.status_code = 200
        response.headers = None
        response.raise_for_status.return_value = None
        session = Mock()
        session.get.return_value = response
        result = TechnologyDetection(session=session).detect('example.com')
        self.assertEqual(result['status'], 'FAILED')

    @patch('core.technology_detection._public_host', return_value=True)
    def test_follows_safe_http_redirect(self, public_host):
        first = self.response({'Location': 'https://example.com/home'})
        first.status_code = 301
        second = self.response(body='<html></html>')
        session = Mock()
        session.get.side_effect = [first, second]
        result = TechnologyDetection(session=session).detect('example.com')
        self.assertEqual(result['status'], 'SUCCESS')
        self.assertEqual(session.get.call_count, 2)

    @patch('core.technology_detection._public_host', return_value=False)
    def test_rejects_non_public_domain_target(self, public_host):
        result = TechnologyDetection().detect('example.com')
        self.assertEqual(result['status'], 'FAILED')


if __name__ == '__main__':
    unittest.main()