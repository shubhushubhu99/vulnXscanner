import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.whois_lookup import NOT_AVAILABLE, WhoisLookup, validate_domain


class TestWhoisValidation(unittest.TestCase):
    def test_normalizes_public_domains(self):
        self.assertEqual(validate_domain(' WWW.Example.COM. '), 'example.com')

    def test_rejects_urls_and_internal_targets(self):
        for value in ('https://example.com', 'localhost', '127.0.0.1', 'example.local'):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_domain(value)


class TestWhoisLookup(unittest.TestCase):
    @patch('core.whois_lookup.whois')
    def test_normalizes_whois_data(self, whois_module):
        whois_module.whois.return_value = type('Record', (), {
            'registrar': 'Example Registrar',
            'creation_date': None,
            'updated_date': None,
            'expiration_date': None,
            'status': ['clientTransferProhibited'],
            'name_servers': ['NS1.EXAMPLE.COM'],
            'whois_server': None,
            'dnssec': None,
            'org': None,
            'country': None,
        })()

        result = WhoisLookup().lookup('example.com')

        self.assertEqual(result['status'], 'SUCCESS')
        self.assertEqual(result['registrar'], 'Example Registrar')
        self.assertEqual(result['creation_date'], NOT_AVAILABLE)
        self.assertEqual(result['name_servers'], ['NS1.EXAMPLE.COM'])

    @patch('core.whois_lookup.whois')
    def test_handles_lookup_failure(self, whois_module):
        whois_module.whois.side_effect = TimeoutError()
        result = WhoisLookup().lookup('example.com')
        self.assertEqual(result['status'], 'ERROR')
        self.assertIn('timed out', result['error'])


if __name__ == '__main__':
    unittest.main()