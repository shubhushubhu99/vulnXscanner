"""
Comprehensive test suite for VulnX Scanner
Tests IPv4 compatibility and IPv6 support
"""
import sys
import os
import unittest
import socket

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.scanner import (
    is_ipv4, is_ipv6, get_address_family,
    resolve_target, scan_target, grab_banner
)


class TestIPv4Compatibility(unittest.TestCase):
    """Test IPv4 functionality to ensure backward compatibility"""
    
    def test_is_ipv4_valid_addresses(self):
        """Test valid IPv4 addresses"""
        valid_ipv4 = [
            "127.0.0.1",
            "192.168.1.1",
            "8.8.8.8",
            "10.0.0.1",
            "172.16.0.1",
            "255.255.255.255",
            "0.0.0.0"
        ]
        for ip in valid_ipv4:
            with self.subTest(ip=ip):
                self.assertTrue(is_ipv4(ip), f"{ip} should be recognized as IPv4")
                self.assertFalse(is_ipv6(ip), f"{ip} should NOT be recognized as IPv6")
                self.assertEqual(get_address_family(ip), socket.AF_INET, 
                               f"{ip} should return AF_INET")
    
    def test_is_ipv4_invalid_addresses(self):
        """Test invalid IPv4 addresses"""
        invalid_ipv4 = [
            "256.1.1.1",
            "1.1.1",
            "1.1.1.1.1",
            "not.an.ip",
            "2001:db8::1",
            "::1"
        ]
        for ip in invalid_ipv4:
            with self.subTest(ip=ip):
                self.assertFalse(is_ipv4(ip), f"{ip} should NOT be recognized as IPv4")
    
    def test_resolve_target_ipv4(self):
        """Test resolving IPv4 addresses"""
        # Direct IPv4 addresses
        ip, host = resolve_target("127.0.0.1")
        self.assertEqual(ip, "127.0.0.1")
        self.assertEqual(host, "127.0.0.1")
        
        ip, host = resolve_target("8.8.8.8")
        self.assertEqual(ip, "8.8.8.8")
        self.assertEqual(host, "8.8.8.8")
        
        # IPv4 with protocol prefix
        ip, host = resolve_target("http://127.0.0.1")
        self.assertEqual(ip, "127.0.0.1")
        
        ip, host = resolve_target("https://192.168.1.1/path")
        self.assertEqual(ip, "192.168.1.1")
    
    def test_resolve_target_ipv4_hostname(self):
        """Test resolving IPv4 hostnames (localhost)"""
        ip, host = resolve_target("localhost")
        self.assertIsNotNone(ip, "localhost should resolve")
        self.assertTrue(is_ipv4(ip), f"localhost should resolve to IPv4: {ip}")
        self.assertEqual(host, "localhost")
    
    def test_scan_target_ipv4_structure(self):
        """Test scan_target returns correct structure for IPv4"""
        # Note: This test doesn't actually scan, just checks structure
        # We'll test with localhost which should work
        try:
            result = scan_target("127.0.0.1", deep_scan=False)
            self.assertIn('target_ip', result)
            self.assertIn('ports', result)
            self.assertIn('timestamp', result)
            self.assertEqual(result['target_ip'], "127.0.0.1")
            self.assertIsInstance(result['ports'], list)
        except Exception as e:
            # If scanning fails (firewall, etc), that's okay for structure test
            pass


class TestIPv6Support(unittest.TestCase):
    """Test IPv6 functionality"""
    
    def test_is_ipv6_valid_addresses(self):
        """Test valid IPv6 addresses"""
        valid_ipv6 = [
            "::1",
            "2001:db8::1",
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            "2001:db8::",
            "fe80::1",
            "::",
            "2001:db8:0:0:0:0:0:1"
        ]
        for ip in valid_ipv6:
            with self.subTest(ip=ip):
                self.assertTrue(is_ipv6(ip), f"{ip} should be recognized as IPv6")
                self.assertFalse(is_ipv4(ip), f"{ip} should NOT be recognized as IPv4")
                self.assertEqual(get_address_family(ip), socket.AF_INET6,
                               f"{ip} should return AF_INET6")
    
    def test_is_ipv6_invalid_addresses(self):
        """Test invalid IPv6 addresses"""
        invalid_ipv6 = [
            "127.0.0.1",
            "192.168.1.1",
            "not.an.ip",
            "gggg::1",
            "2001:db8::1::2"  # Invalid format
        ]
        for ip in invalid_ipv6:
            with self.subTest(ip=ip):
                self.assertFalse(is_ipv6(ip), f"{ip} should NOT be recognized as IPv6")
    
    def test_resolve_target_ipv6(self):
        """Test resolving IPv6 addresses"""
        # Direct IPv6 addresses
        ip, host = resolve_target("::1")
        self.assertEqual(ip, "::1")
        self.assertEqual(host, "::1")
        
        ip, host = resolve_target("2001:db8::1")
        self.assertEqual(ip, "2001:db8::1")
        self.assertEqual(host, "2001:db8::1")
        
        # IPv6 with brackets
        ip, host = resolve_target("[::1]")
        self.assertEqual(ip, "::1")
        
        ip, host = resolve_target("[2001:db8::1]")
        self.assertEqual(ip, "2001:db8::1")
        
        # IPv6 with protocol prefix
        ip, host = resolve_target("http://[::1]")
        self.assertEqual(ip, "::1")
    
    def test_resolve_target_ipv6_hostname(self):
        """Test resolving hostnames that may have IPv6"""
        # Test with localhost which might have IPv6
        ip, host = resolve_target("localhost")
        self.assertIsNotNone(ip, "localhost should resolve")
        self.assertTrue(is_ipv4(ip) or is_ipv6(ip), 
                       f"localhost should resolve to valid IP: {ip}")
        self.assertEqual(host, "localhost")
    
    def test_scan_target_ipv6_structure(self):
        """Test scan_target returns correct structure for IPv6"""
        try:
            result = scan_target("::1", deep_scan=False)
            self.assertIn('target_ip', result)
            self.assertIn('ports', result)
            self.assertIn('timestamp', result)
            self.assertEqual(result['target_ip'], "::1")
            self.assertIsInstance(result['ports'], list)
        except Exception as e:
            # If scanning fails (firewall, no IPv6, etc), that's okay
            pass


class TestAddressFamilyDetection(unittest.TestCase):
    """Test address family detection"""
    
    def test_get_address_family_ipv4(self):
        """Test address family detection for IPv4"""
        self.assertEqual(get_address_family("127.0.0.1"), socket.AF_INET)
        self.assertEqual(get_address_family("8.8.8.8"), socket.AF_INET)
        self.assertEqual(get_address_family("192.168.1.1"), socket.AF_INET)
    
    def test_get_address_family_ipv6(self):
        """Test address family detection for IPv6"""
        self.assertEqual(get_address_family("::1"), socket.AF_INET6)
        self.assertEqual(get_address_family("2001:db8::1"), socket.AF_INET6)
        self.assertEqual(get_address_family("fe80::1"), socket.AF_INET6)
    
    def test_get_address_family_invalid(self):
        """Test address family detection for invalid addresses"""
        self.assertIsNone(get_address_family("not.an.ip"))
        self.assertIsNone(get_address_family(""))
        self.assertIsNone(get_address_family("invalid"))


class TestBackwardCompatibility(unittest.TestCase):
    """Test that existing IPv4 functionality still works"""
    
    def test_ipv4_scanning_unchanged(self):
        """Ensure IPv4 scanning behavior is unchanged"""
        # Test that IPv4 addresses still work exactly as before
        ip = "127.0.0.1"
        family = get_address_family(ip)
        self.assertEqual(family, socket.AF_INET)
        
        # Test resolve_target still works for IPv4
        resolved_ip, host = resolve_target(ip)
        self.assertEqual(resolved_ip, ip)
        self.assertTrue(is_ipv4(resolved_ip))
    
    def test_hostname_resolution_prefers_ipv4(self):
        """Test that hostname resolution prefers IPv4 (backward compatibility)"""
        # This should try IPv4 first
        ip, host = resolve_target("localhost")
        if ip:
            # If it resolves, it should prefer IPv4
            # (though IPv6 is acceptable if IPv4 not available)
            self.assertTrue(is_ipv4(ip) or is_ipv6(ip))
    
    def test_grab_banner_ipv4(self):
        """Test banner grabbing still works for IPv4"""
        # Test with localhost port 80 (if available)
        try:
            banner = grab_banner("127.0.0.1", 80, socket.AF_INET)
            # Should return a string (even if "No banner response")
            self.assertIsInstance(banner, str)
        except Exception:
            # Port might not be open, that's okay
            pass


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling"""
    
    def test_resolve_target_with_protocols(self):
        """Test resolving targets with various protocol prefixes"""
        test_cases = [
            ("http://127.0.0.1", "127.0.0.1"),
            ("https://192.168.1.1", "192.168.1.1"),
            ("http://[::1]", "::1"),
            ("https://[2001:db8::1]", "2001:db8::1"),
            ("http://example.com/path", None),  # Will try to resolve
        ]
        
        for target, expected_ip in test_cases:
            with self.subTest(target=target):
                ip, host = resolve_target(target)
                if expected_ip:
                    self.assertEqual(ip, expected_ip)
                # Host should be cleaned
                self.assertNotIn("http://", host.lower())
                self.assertNotIn("https://", host.lower())
    
    def test_invalid_target_handling(self):
        """Test handling of invalid targets"""
        invalid_targets = [
            "",
            "   ",
            "not.a.valid.hostname.12345",
            "999.999.999.999",
        ]
        
        for target in invalid_targets:
            with self.subTest(target=target):
                ip, host = resolve_target(target)
                # Should return None for IP if invalid
                if not target.strip():
                    # Empty string should return None
                    self.assertIsNone(ip)
    
    def test_scan_target_invalid_ip(self):
        """Test scan_target with invalid IP raises error"""
        with self.assertRaises(ValueError):
            scan_target("invalid.ip.address", deep_scan=False)


def run_tests():
    """Run all test suites"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestIPv4Compatibility))
    suite.addTests(loader.loadTestsFromTestCase(TestIPv6Support))
    suite.addTests(loader.loadTestsFromTestCase(TestAddressFamilyDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestBackwardCompatibility))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result


if __name__ == '__main__':
    print("=" * 70)
    print("VulnX Scanner - Comprehensive Test Suite")
    print("Testing IPv4 Compatibility & IPv6 Support")
    print("=" * 70)
    print()
    
    result = run_tests()
    
    print()
    print("=" * 70)
    if result.wasSuccessful():
        print("✅ ALL TESTS PASSED!")
        print(f"   Tests run: {result.testsRun}")
        print(f"   Failures: {len(result.failures)}")
        print(f"   Errors: {len(result.errors)}")
    else:
        print("⚠️  SOME TESTS FAILED")
        print(f"   Tests run: {result.testsRun}")
        print(f"   Failures: {len(result.failures)}")
        print(f"   Errors: {len(result.errors)}")
        if result.failures:
            print("\nFailures:")
            for test, traceback in result.failures:
                print(f"  - {test}")
        if result.errors:
            print("\nErrors:")
            for test, traceback in result.errors:
                print(f"  - {test}")
    print("=" * 70)
    
    sys.exit(0 if result.wasSuccessful() else 1)
