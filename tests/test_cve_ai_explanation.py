"""Tests for the CVE AI explanation feature.

Covers all 10 cases required by the feature spec:

 1. Valid CVE explanation request (happy path).
 2. Missing CVE data (cve_data is None).
 3. Missing CVE ID inside cve_data.
 4. AI API generic failure (exception).
 5. AI timeout (requests.Timeout).
 6. AI quota exceeded (HTTP 429).
 7. Multiple CVEs — each gets an independent explanation.
 8. Original NVD CVE data unchanged after explanation.
 9. AI NOT called automatically during scanning.
10. AI called only after explicit user action (endpoint route function).

Note: Flask test client is skipped due to a Flask 2.2.5/Werkzeug 3.x
incompatibility in this environment.  Test 10 instead exercises the
route handler directly through its Python interface.
"""

import json
import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Ensure src/ is on the path for all test imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ── Shared fixtures ───────────────────────────────────────────────────────────

SAMPLE_CVE = {
    "id": "CVE-2021-44228",
    "description": (
        "Apache Log4j2 2.0-beta9 through 2.14.1 JNDI features used in "
        "configuration, log messages, and parameters do not protect against "
        "attacker controlled LDAP and other JNDI related endpoints."
    ),
    "cvss_score": 10.0,
    "severity": "CRITICAL",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
    "published": "2021-12-10T00:00:00.000",
    "last_modified": "2022-01-01T00:00:00.000",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    "affected_products": ["log4j"],
    "affected_versions": ["2.0-beta9", "2.14.1"],
    "vulnerable": True,
}

GOOD_GEMINI_JSON = json.dumps({
    "cve_id": "CVE-2021-44228",
    "what_is_this": "A flaw in the logging library allows remote code execution.",
    "why_should_i_care": "Attackers can run arbitrary code without authentication.",
    "what_could_happen": "Full server compromise.",
    "am_i_affected": "Apache Log4j 2.0-beta9 through 2.14.1.",
    "what_should_i_do": "Upgrade to Log4j 2.17.1 or later.",
    "how_do_i_verify_the_fix": "Confirm no vulnerable jar remains in the classpath.",
})


def _make_rest_response(text, status=200):
    """Build a mock REST response matching Gemini's nested JSON structure."""
    mock_resp = MagicMock()
    mock_resp.status_code = status
    mock_resp.json.return_value = {
        "candidates": [{"content": {"parts": [{"text": text}]}}]
    }
    return mock_resp


# ── Unit tests for explain_cve() service ─────────────────────────────────────


class TestExplainCve(unittest.TestCase):
    """Tests for src.services.ai_service.explain_cve (service layer only)."""

    def setUp(self):
        self._key_p = patch("src.services.ai_service.GEMINI_API_KEY", "fake-key")
        self._sdk_p = patch("src.services.ai_service.genai_client", None)
        self._key_p.start()
        self._sdk_p.start()

    def tearDown(self):
        self._key_p.stop()
        self._sdk_p.stop()

    # ── Test 1 ────────────────────────────────────────────────────────────────

    @patch("src.services.ai_service.requests.post")
    def test_1_valid_cve_explanation(self, mock_post):
        """Valid request returns success=True with all structured fields."""
        mock_post.return_value = _make_rest_response(GOOD_GEMINI_JSON)

        from src.services.ai_service import explain_cve

        result = explain_cve(SAMPLE_CVE)

        self.assertTrue(result["success"], msg=result)
        data = result["data"]
        self.assertEqual(data["cve_id"], "CVE-2021-44228")
        for key in ("what_is_this", "why_should_i_care", "what_could_happen",
                    "am_i_affected", "what_should_i_do", "how_do_i_verify_the_fix"):
            self.assertIn(key, data, msg=f"Missing field: {key}")
        self.assertNotIn("_status_code", result)

    # ── Test 2 ────────────────────────────────────────────────────────────────

    def test_2a_missing_cve_data_none(self):
        """explain_cve(None) returns 400 without touching the AI."""
        from src.services.ai_service import explain_cve

        result = explain_cve(None)
        self.assertFalse(result["success"])
        self.assertEqual(result.get("_status_code"), 400)

    def test_2b_missing_cve_data_empty(self):
        """explain_cve({}) with no id field returns 400."""
        from src.services.ai_service import explain_cve

        result = explain_cve({})
        self.assertFalse(result["success"])
        self.assertEqual(result.get("_status_code"), 400)

    # ── Test 3 ────────────────────────────────────────────────────────────────

    def test_3_missing_cve_id(self):
        """cve_data without 'id' or 'cve_id' returns 400 mentioning 'id'."""
        from src.services.ai_service import explain_cve

        result = explain_cve({"description": "Some vulnerability", "cvss_score": 7.5})
        self.assertFalse(result["success"])
        self.assertEqual(result.get("_status_code"), 400)
        self.assertIn("id", result["error"].lower())

    # ── Test 4 ────────────────────────────────────────────────────────────────

    @patch("src.services.ai_service.requests.post")
    def test_4_ai_generic_failure(self, mock_post):
        """Unexpected exception from requests propagates as a 500 error."""
        mock_post.side_effect = RuntimeError("Unexpected internal error")

        from src.services.ai_service import explain_cve

        result = explain_cve(SAMPLE_CVE)
        self.assertFalse(result["success"])
        self.assertEqual(result.get("_status_code"), 500)

    # ── Test 5 ────────────────────────────────────────────────────────────────

    @patch("src.services.ai_service.requests.post")
    def test_5_ai_timeout(self, mock_post):
        """requests.Timeout from Gemini REST returns a 504 error."""
        import requests as req_lib
        mock_post.side_effect = req_lib.Timeout("Connection timed out")

        from src.services.ai_service import explain_cve

        result = explain_cve(SAMPLE_CVE)
        self.assertFalse(result["success"])
        self.assertEqual(result.get("_status_code"), 504)
        self.assertIn("timed out", result["error"].lower())

    # ── Test 6 ────────────────────────────────────────────────────────────────

    @patch("src.services.ai_service.requests.post")
    def test_6_ai_quota_exceeded_429(self, mock_post):
        """HTTP 429 from Gemini returns a rate-limit error with status 429."""
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_post.return_value = mock_resp

        from src.services.ai_service import explain_cve

        result = explain_cve(SAMPLE_CVE)
        self.assertFalse(result["success"])
        self.assertEqual(result.get("_status_code"), 429)
        self.assertIn("rate limit", result["error"].lower())

    # ── Test 7 ────────────────────────────────────────────────────────────────

    @patch("src.services.ai_service.requests.post")
    def test_7_multiple_cves_independent(self, mock_post):
        """Two CVEs with distinct IDs and CPEs get distinct explanations."""
        # CVE A: Log4Shell
        cve_a = {
            "id": "CVE-2021-44228",
            "description": "Log4j JNDI vulnerability",
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
            "published": "2021-12-10T00:00:00.000",
            "last_modified": "2022-01-01T00:00:00.000",
            "references": [],
            "affected_products": [],
            "affected_versions": [],
        }
        # CVE B: Apache path traversal — completely separate product+CPE
        cve_b = {
            "id": "CVE-2021-41773",
            "description": "Path traversal in Apache HTTP Server 2.4.49",
            "cvss_score": 7.5,
            "severity": "HIGH",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            "published": "2021-10-05T00:00:00.000",
            "last_modified": "2021-11-01T00:00:00.000",
            "references": [],
            "affected_products": [],
            "affected_versions": [],
        }

        def side_effect(*args, **kwargs):
            prompt = kwargs.get("json", {})["contents"][0]["parts"][0]["text"]
            # Discriminate purely on the CVE ID embedded in the prompt
            if "CVE-2021-44228" in prompt:
                text = json.dumps({"cve_id": "CVE-2021-44228",
                                   "what_is_this": "Log4Shell explanation"})
            else:
                text = json.dumps({"cve_id": "CVE-2021-41773",
                                   "what_is_this": "Path traversal explanation"})
            return _make_rest_response(text)

        mock_post.side_effect = side_effect

        from src.services.ai_service import explain_cve

        res_a = explain_cve(cve_a)
        res_b = explain_cve(cve_b)

        self.assertTrue(res_a["success"])
        self.assertTrue(res_b["success"])
        self.assertEqual(res_a["data"]["cve_id"], "CVE-2021-44228")
        self.assertEqual(res_b["data"]["cve_id"], "CVE-2021-41773")
        # Core requirement: the two summaries must differ
        self.assertNotEqual(res_a["data"]["what_is_this"], res_b["data"]["what_is_this"])

    # ── Test 8 ────────────────────────────────────────────────────────────────

    @patch("src.services.ai_service.requests.post")
    def test_8_nvd_data_unchanged_after_explanation(self, mock_post):
        """The original cve_data dict passed to explain_cve is not modified."""
        mock_post.return_value = _make_rest_response(GOOD_GEMINI_JSON)

        from src.services.ai_service import explain_cve

        original = dict(SAMPLE_CVE)
        snapshot = dict(SAMPLE_CVE)

        explain_cve(original)

        for key, value in snapshot.items():
            self.assertEqual(original[key], value,
                             msg=f"Field '{key}' was mutated by explain_cve")

    # ── Test 9 ────────────────────────────────────────────────────────────────

    @patch("src.services.ai_service.explain_cve")
    def test_9_ai_not_called_during_scan(self, mock_explain_cve):
        """get_cves_for_service (the scan path) must never call explain_cve."""
        with (
            patch("src.services.vulnerability.cve_service.parse_banner") as mp,
            patch("src.services.vulnerability.cve_service.map_to_cpe") as mm,
            patch("src.services.vulnerability.cve_service.fetch_cves_for_cpe") as mf,
        ):
            from src.services.vulnerability.models import CveData

            mp.return_value = ("apache", "log4j", "2.14.1")
            mm.return_value = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
            mf.return_value = [
                CveData(
                    id="CVE-2021-44228",
                    description="Log4j",
                    cvss_score=10.0,
                    severity="CRITICAL",
                    cvss_vector="CVSS:3.1/...",
                    published="2021-12-10T00:00:00.000",
                    last_modified="2022-01-01T00:00:00.000",
                    cpe="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                    references=[],
                )
            ]

            from src.services.vulnerability.cve_service import get_cves_for_service
            result = get_cves_for_service("HTTP", "Apache Log4j 2.14.1")

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["cve_count"], 1)
        mock_explain_cve.assert_not_called()


# ── Test 10: Endpoint isolation using Flask request context ──────────────────


class TestCveExplainEndpointRoutes(unittest.TestCase):
    """Test 10: /cve_explain calls explain_cve only on explicit user action.

    Uses app.test_request_context() to avoid the Flask 2.2.5 + Werkzeug 3.x
    incompatibility that prevents test_client() from initialising.
    """

    def setUp(self):
        import app as app_module
        self.app = app_module.app

    # ── Test 10a ──────────────────────────────────────────────────────────────

    @patch("routes.api.explain_cve")
    def test_10a_endpoint_calls_explain_cve_on_valid_request(self, mock_explain):
        """explain_cve is called exactly once when valid cve_data is POSTed."""
        mock_explain.return_value = {
            "success": True,
            "data": {
                "cve_id": "CVE-2021-44228",
                "what_is_this": "Test summary",
                "why_should_i_care": "Test danger",
                "what_could_happen": "Test impact",
                "am_i_affected": "Test system",
                "what_should_i_do": "Test action",
                "how_do_i_verify_the_fix": "Test verification",
            },
        }

        with self.app.test_request_context(
            "/cve_explain",
            method="POST",
            json={"cve_data": SAMPLE_CVE},
            content_type="application/json",
        ):
            from routes.api import cve_explain

            response = cve_explain()
            # Flask returns (Response, status_code) or just Response
            body_obj = response[0] if isinstance(response, tuple) else response
            body = body_obj.get_json() if hasattr(body_obj, "get_json") else body_obj

        mock_explain.assert_called_once_with(SAMPLE_CVE)
        self.assertTrue(body["success"])

    # ── Test 10b ──────────────────────────────────────────────────────────────

    @patch("routes.api.explain_cve")
    def test_10b_endpoint_rejects_missing_cve_data(self, mock_explain):
        """explain_cve is NOT called when cve_data is absent."""
        with self.app.test_request_context(
            "/cve_explain",
            method="POST",
            json={},
            content_type="application/json",
        ):
            from routes.api import cve_explain

            response = cve_explain()
            status_code = response[1] if isinstance(response, tuple) else 200
            body_obj = response[0] if isinstance(response, tuple) else response
            body = body_obj.get_json() if hasattr(body_obj, "get_json") else body_obj

        self.assertEqual(status_code, 400)
        self.assertFalse(body["success"])
        mock_explain.assert_not_called()

    # ── Test 10c ──────────────────────────────────────────────────────────────

    @patch("routes.api.explain_cve")
    def test_10c_endpoint_rejects_missing_cve_id(self, mock_explain):
        """explain_cve is NOT called when cve_data has no 'id' field."""
        with self.app.test_request_context(
            "/cve_explain",
            method="POST",
            json={"cve_data": {"description": "no id here"}},
            content_type="application/json",
        ):
            from routes.api import cve_explain

            response = cve_explain()
            status_code = response[1] if isinstance(response, tuple) else 200

        self.assertEqual(status_code, 400)
        mock_explain.assert_not_called()


if __name__ == "__main__":
    unittest.main()
