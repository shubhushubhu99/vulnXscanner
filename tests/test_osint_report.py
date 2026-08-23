import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.osint_report import build_osint_report_data, generate_osint_pdf


def scan_payload():
    return {
        'target': 'long.example.com',
        'url_domain_intelligence': {
            'status': 'SUCCESS', 'original_input': 'https://long.example.com/path',
            'hostname': 'long.example.com', 'scheme': 'https',
        },
        'whois': {'status': 'ERROR'},
        'ip_resolution': {'status': 'SUCCESS', 'addresses': ['1.2.3.4', '5.6.7.8']},
        'ip_geolocation': {'status': 'SUCCESS', 'country': 'US', 'isp': 'Example ISP'},
        'dns_relationship_map': {
            'status': 'SUCCESS', 'domain': 'long.example.com',
            'nodes': [
                {'id': 'domain:long.example.com', 'label': 'long.example.com', 'type': 'DOMAIN'},
                {'id': 'record:A', 'label': 'A', 'type': 'RECORD'},
                {'id': 'ip:1.2.3.4', 'label': '1.2.3.4', 'type': 'IP'},
                {'id': 'record:TXT', 'label': 'TXT', 'type': 'RECORD'},
                {'id': 'txt:long', 'label': 'v=spf1 ' + ('include:example.com ' * 50), 'type': 'TXT'},
            ],
            'edges': [
                {'source': 'domain:long.example.com', 'target': 'record:A', 'relationship': 'A'},
                {'source': 'record:A', 'target': 'ip:1.2.3.4', 'relationship': ''},
                {'source': 'domain:long.example.com', 'target': 'record:TXT', 'relationship': 'TXT'},
                {'source': 'record:TXT', 'target': 'txt:long', 'relationship': ''},
            ],
        },
        'technology_detection': {'status': 'FAILED', 'technologies': []},
    }


class TestOsintReport(unittest.TestCase):
    def test_report_uses_graph_values_and_omits_empty_record_types(self):
        report = build_osint_report_data(scan_payload())
        pdf, _ = generate_osint_pdf(scan_payload())
        pdf_text = pdf.getvalue().decode('latin1')

        self.assertEqual(report['dns'][0], ('A', '1.2.3.4', ''))
        self.assertEqual(report['dns'][1][0], 'TXT')
        self.assertNotIn(('AAAA', '', ''), report['dns'])
        self.assertEqual(report['resolution']['addresses'], ['1.2.3.4', '5.6.7.8'])
        self.assertEqual(report['technology_status'], 'FAILED')
        self.assertNotIn('OSINT RISK SCORE', pdf_text)
        self.assertNotIn('Risk Level', pdf_text)

    def test_partial_and_unavailable_sections_still_generate_pdf(self):
        pdf, filename = generate_osint_pdf(scan_payload())

        self.assertEqual(pdf.read(4), b'%PDF')
        self.assertEqual(filename, 'vulnxscanner_long.example.com_OSINT_Report.pdf')
        self.assertGreater(len(pdf.getvalue()), 1000)

    def test_no_data_payload_generates_unavailable_report(self):
        report = build_osint_report_data({})
        pdf, filename = generate_osint_pdf({})

        self.assertEqual(report['successful_modules'], 0)
        self.assertEqual(filename, 'vulnxscanner_unknown-target_OSINT_Report.pdf')
        self.assertEqual(pdf.read(4), b'%PDF')


if __name__ == '__main__':
    unittest.main()