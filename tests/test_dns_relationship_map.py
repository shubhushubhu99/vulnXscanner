import os
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.dns_relationship_map import DNSRelationshipMap


class TestDNSRelationshipMap(unittest.TestCase):
    def make_resolver(self, records):
        resolver = Mock()

        def resolve(domain, record_type, lifetime):
            answers = records.get(record_type, [])
            if not answers:
                import dns.resolver
                raise dns.resolver.NoAnswer()
            return [Mock(to_text=lambda value=value: value) for value in answers]

        resolver.resolve.side_effect = resolve
        return resolver

    def test_builds_nodes_and_edges_for_record_types(self):
        records = {
            'CNAME': ['target.example.net.'],
            'MX': ['10 mail.example.com.'],
            'NS': ['ns1.example.com.'],
            'TXT': ['"v=spf1 -all"'],
            'SOA': ['ns1.example.com. hostmaster.example.com. 1 3600 600 86400 300'],
            'CAA': ['0 issue "letsencrypt.org"'],
        }
        graph = DNSRelationshipMap(resolver=self.make_resolver(records)).build(
            'example.com',
            {'addresses': ['93.184.216.34', '2001:db8::1']},
        )
        node_types = {node['type'] for node in graph['nodes']}
        relationships = {edge['relationship'] for edge in graph['edges'] if edge['relationship']}
        self.assertEqual(graph['status'], 'SUCCESS')
        self.assertIn('DOMAIN', node_types)
        self.assertIn('RECORD', node_types)
        self.assertIn('IP', node_types)
        self.assertIn('MAIL', node_types)
        self.assertIn('NAMESERVER', node_types)
        self.assertEqual(relationships, {'A', 'AAAA', 'CNAME', 'MX', 'NS'})
        self.assertNotIn('TXT', node_types)
        self.assertNotIn('SOA', node_types)
        self.assertNotIn('CAA', node_types)
        self.assertEqual(graph['record_summary']['CAA'], 1)
        self.assertEqual(graph['metadata']['CAA'][0]['issuer'], 'letsencrypt.org')
        self.assertEqual(graph['metadata']['SOA'][0]['primary_nameserver'], 'ns1.example.com')

    def test_deduplicates_values(self):
        resolver = self.make_resolver({'NS': ['ns1.example.com.', 'ns1.example.com.']})
        graph = DNSRelationshipMap(resolver=resolver).build('example.com')
        self.assertEqual(len(graph['edges']), 2)
        self.assertEqual(len(graph['nodes']), 3)

    def test_standalone_map_queries_address_records(self):
        resolver = self.make_resolver({'A': ['93.184.216.34']})
        graph = DNSRelationshipMap(resolver=resolver).build('example.com')
        self.assertEqual(graph['status'], 'SUCCESS')
        self.assertEqual(graph['edges'][0]['relationship'], 'A')

    def test_empty_dns_returns_no_relationships(self):
        graph = DNSRelationshipMap(resolver=self.make_resolver({})).build('example.com')
        self.assertEqual(graph['status'], 'NOT AVAILABLE')
        self.assertEqual(len(graph['nodes']), 1)
        self.assertEqual(graph['edges'], [])

    def test_invalid_domain_is_rejected(self):
        with self.assertRaises(ValueError):
            DNSRelationshipMap().build('https://example.com')


if __name__ == '__main__':
    unittest.main()