import unittest
from unittest.mock import patch, MagicMock
from src.socket_events import run_cve_enrichment_task

class TestSocketEvents(unittest.TestCase):

    @patch('src.socket_events.socketio.emit')
    @patch('src.socket_events.get_cves_for_service')
    def test_cve_enrichment_cves_found(self, mock_get_cves, mock_emit):
        """Test backend behavior when CVEs are found."""
        mock_get_cves.return_value = {
            "status": "success",
            "product": "openssh",
            "version": "8.9p1",
            "cve_count": 5,
            "cves": [{"id": "CVE-TEST", "cvss_score": 9.8}]
        }
        
        # Valid scan result mock (port, service, banner, severity, threat)
        res_list = [(22, "SSH", "SSH-2.0-OpenSSH_8.9p1", "MEDIUM", "N/A")]
        
        run_cve_enrichment_task("127.0.0.1", res_list)
        
        # Verify emit was called correctly
        mock_emit.assert_called_once()
        args, kwargs = mock_emit.call_args
        self.assertEqual(args[0], 'cve_results')
        
        data = args[1]
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["target"], "127.0.0.1")
        self.assertEqual(data["port"], 22)
        self.assertEqual(data["service"], "SSH")
        self.assertEqual(data["cve_count"], 5)

    @patch('src.socket_events.socketio.emit')
    @patch('src.socket_events.get_cves_for_service')
    def test_cve_enrichment_no_cves(self, mock_get_cves, mock_emit):
        """Test backend behavior when no CVEs are found (clean empty handling)."""
        mock_get_cves.return_value = {
            "status": "success",
            "product": "nginx",
            "version": "1.25.0",
            "cve_count": 0,
            "cves": []
        }
        
        res_list = [(80, "HTTP", "nginx/1.25.0", "LOW", "N/A")]
        
        run_cve_enrichment_task("127.0.0.1", res_list)
        
        mock_emit.assert_called_once()
        data = mock_emit.call_args[0][1]
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["cve_count"], 0)
        self.assertEqual(len(data["cves"]), 0)

    @patch('src.socket_events.socketio.emit')
    @patch('src.socket_events.logger.error')
    @patch('src.socket_events.get_cves_for_service')
    def test_cve_enrichment_nvd_failure(self, mock_get_cves, mock_logger, mock_emit):
        """Test that an NVD API failure/exception emits an error status without crashing."""
        mock_get_cves.side_effect = Exception("NVD API Timeout")
        
        res_list = [(443, "HTTPS", "Apache/2.4.49", "MEDIUM", "N/A")]
        
        run_cve_enrichment_task("127.0.0.1", res_list)
        
        mock_logger.assert_called()
        mock_emit.assert_called_once()
        data = mock_emit.call_args[0][1]
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["target"], "127.0.0.1")
        self.assertEqual(data["port"], 443)
        self.assertEqual(data["cve_count"], 0)

    @patch('src.socket_events.socketio.emit')
    def test_cve_enrichment_malformed_scanner_result(self, mock_emit):
        """Test that malformed/missing banners are handled gracefully without errors."""
        res_list = [(8080, "HTTP", "No banner response", "LOW", "N/A")]
        
        run_cve_enrichment_task("127.0.0.1", res_list)
        
        # Should not emit anything for empty/no banner response
        mock_emit.assert_not_called()

if __name__ == '__main__':
    unittest.main()
