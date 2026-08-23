import json

import requests

from extensions import GEMINI_API_KEY, GEMINI_MODEL, genai_client, logger


def _extract_gemini_text(obj):
    """Recursively extract text from Gemini SDK or REST response."""
    if not obj:
        return ""
    if isinstance(obj, str):
        return obj.strip()
    if isinstance(obj, dict):
        for key in ("candidates", "content", "text", "output", "response"):
            if key in obj:
                val = obj[key]
                if isinstance(val, list) and val:
                    return " ".join(filter(None, [_extract_gemini_text(v) for v in val]))
                if isinstance(val, dict):
                    return _extract_gemini_text(val)
                if isinstance(val, str):
                    return val.strip()
        for v in obj.values():
            t = _extract_gemini_text(v)
            if t:
                return t
    if isinstance(obj, list):
        for item in obj:
            t = _extract_gemini_text(item)
            if t:
                return t
    return ""


def _call_gemini_rest(prompt):
    """Send prompt to Gemini REST endpoint and return response object."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
    params = {"key": GEMINI_API_KEY}
    headers = {"Content-Type": "application/json"}
    if isinstance(GEMINI_API_KEY, str) and (
        GEMINI_API_KEY.startswith("ya29.") or GEMINI_API_KEY.lower().startswith("bearer ")
    ):
        token = GEMINI_API_KEY.split(" ", 1)[-1]
        headers["Authorization"] = f"Bearer {token}"
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    return requests.post(url, headers=headers, params=params, json=payload, timeout=12)


def _handle_gemini_rest_errors(resp):
    """Return a structured error payload if status >= 400, else None."""
    if resp.status_code == 429:
        return {"success": False, "error": "Rate limit exceeded. Please try again later.", "_status_code": 429}
    if resp.status_code == 401:
        return {"success": False, "error": "Unauthorized: invalid Gemini API key or token.", "_status_code": 401}
    if resp.status_code >= 400:
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        return {
            "success": False,
            "error": "Gemini API error",
            "status": resp.status_code,
            "detail": body,
            "_status_code": resp.status_code,
        }
    return None


def generate_port_analysis(port, service, banner, severity):
    if not port:
        return {"success": False, "error": "Port number is required", "_status_code": 400}
    if not GEMINI_API_KEY:
        return {"success": False, "error": "Gemini API key not configured", "_status_code": 503}

    prompt = f"""Analyze this port scan result in SIMPLE words for non-technical users.

CRITICAL: Output ONLY plain text. NO HTML tags. NO markdown. NO formatting symbols.

Port: {port}
Service: {service}
Banner: {banner}
Risk: {severity}

RESPONSE FORMAT (EXACTLY as shown):

1. **What is this port?**
[1-2 lines explaining simply]

2. **Why is it risky?**
* [Risk point]
* [Risk point]
* [Risk point]

3. **How to secure it?**
* [Action]
* [Action]
* [Action]
* [Action]

4. **Risk score:** [LOW/MEDIUM/HIGH/CRITICAL]

RULES:
- Use ONLY asterisks (*) for bullet points
- Use ONLY numbers and dots (1. 2. 3.) for lists
- NO HTML tags whatsoever
- SHORT sentences only
- Simple English, NO technical jargon
- Keep under 200 words total"""

    if genai_client:
        try:
            logger.info("Calling Gemini via google.genai SDK")
            sdk_resp = genai_client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
            analysis_text = getattr(sdk_resp, "text", None)
            if not analysis_text:
                try:
                    resp_json = (
                        sdk_resp.to_dict()
                        if hasattr(sdk_resp, "to_dict")
                        else json.loads(json.dumps(sdk_resp, default=lambda o: getattr(o, "__dict__", str(o))))
                    )
                except Exception:
                    resp_json = str(sdk_resp)
                analysis_text = _extract_gemini_text(resp_json) or json.dumps(resp_json)
            return {"success": True, "data": {"analysis_html": analysis_text, "port": port, "service": service}}
        except Exception as e:
            logger.error("google.genai SDK call failed: %s", e)

    try:
        logger.info("Sending request to Gemini REST for port %s", port)
        resp = _call_gemini_rest(prompt)
        logger.info("Gemini response status: %s", resp.status_code)
        err = _handle_gemini_rest_errors(resp)
        if err:
            return err
        analysis_text = _extract_gemini_text(resp.json()) or json.dumps(resp.json())
        return {"success": True, "data": {"analysis_html": analysis_text, "port": port, "service": service}}
    except requests.Timeout:
        return {"success": False, "error": "Gemini request timed out", "_status_code": 504}
    except requests.RequestException as e:
        return {"success": False, "error": "Network error when calling Gemini", "detail": str(e), "_status_code": 502}
    except Exception as e:
        logger.error("Unexpected error during AI analysis: %s", e)
        return {"success": False, "error": "Failed to generate AI analysis", "detail": str(e), "_status_code": 500}


def generate_db_analysis(name, description, evidence, risk, recommendation):
    if not name:
        return {"success": False, "error": "Vulnerability name is required", "_status_code": 400}
    if not GEMINI_API_KEY:
        return {"success": False, "error": "Gemini API key not configured", "_status_code": 503}

    prompt = f"""Analyze this database vulnerability in SIMPLE words for non-technical users.

CRITICAL: Output ONLY plain text. NO HTML tags. NO markdown. NO formatting symbols.

Vulnerability: {name}
Description: {description}
Evidence: {evidence}
Risk Level: {risk}
Current Recommendation: {recommendation}

RESPONSE FORMAT (EXACTLY as shown):

1. **What is this vulnerability?**
[1-2 lines explaining simply what went wrong]

2. **Why is it dangerous?**
* [Risk point]
* [Risk point]
* [Risk point]

3. **How to fix it?**
* [Action]
* [Action]
* [Action]
* [Action]

4. **How to prevent it in future?**
* [Prevention measure]
* [Prevention measure]
* [Prevention measure]

5. **Risk Score:** [LOW/MEDIUM/HIGH/CRITICAL]

RULES:
- Use ONLY asterisks (*) for bullet points
- Use ONLY numbers and dots (1. 2. 3.) for lists
- NO HTML tags whatsoever
- SHORT sentences only
- Simple English, NO technical jargon
- Keep under 250 words total"""

    if genai_client:
        try:
            logger.info("Calling Gemini via google.genai SDK for db vulnerability analysis")
            sdk_resp = genai_client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
            analysis_text = getattr(sdk_resp, "text", None)
            if not analysis_text:
                try:
                    resp_json = (
                        sdk_resp.to_dict()
                        if hasattr(sdk_resp, "to_dict")
                        else json.loads(json.dumps(sdk_resp, default=lambda o: getattr(o, "__dict__", str(o))))
                    )
                except Exception:
                    resp_json = str(sdk_resp)
                analysis_text = _extract_gemini_text(resp_json) or json.dumps(resp_json)
            return {"success": True, "data": {"analysis_html": analysis_text, "name": name, "risk": risk}}
        except Exception as e:
            logger.error("google.genai SDK call failed for db analysis: %s", e)

    try:
        logger.info("Sending request to Gemini REST for db vulnerability: %s", name)
        resp = _call_gemini_rest(prompt)
        logger.info("Gemini response status: %s", resp.status_code)
        err = _handle_gemini_rest_errors(resp)
        if err:
            return err
        analysis_text = _extract_gemini_text(resp.json()) or json.dumps(resp.json())
        return {"success": True, "data": {"analysis_html": analysis_text, "name": name, "risk": risk}}
    except requests.Timeout:
        return {"success": False, "error": "Gemini request timed out", "_status_code": 504}
    except requests.RequestException as e:
        return {"success": False, "error": "Network error when calling Gemini", "detail": str(e), "_status_code": 502}
    except Exception as e:
        logger.error("Unexpected error during db vulnerability AI analysis: %s", e)
        return {"success": False, "error": "Failed to generate AI analysis", "detail": str(e), "_status_code": 500}


def explain_cve(cve_data: dict) -> dict:
    """Generate a plain-language AI explanation for a single CVE.

    Receives factual NVD data and returns a structured explanation answering:
    what the vulnerability is, why it is dangerous, what an attacker could do,
    who is affected, what to do, whether upgrading is required, and what to
    verify after fixing.

    The AI must NOT invent facts — it explains only the supplied NVD data.

    Args:
        cve_data: dict with keys from CveData.to_dict() (id, description,
                  cvss_score, severity, cvss_vector, cpe, published,
                  last_modified, references, affected_products,
                  affected_versions).

    Returns:
        dict: {
            "success": True,
            "data": {
                "cve_id": str,
                "what_is_this": str,
                "why_should_i_care": str,
                "what_could_happen": str,
                "am_i_affected": str,
                "what_should_i_do": str,
                "how_do_i_verify_the_fix": str
            }
        }
        or
        dict: {"success": False, "error": str, "_status_code": int}
    """
    if not cve_data:
        return {"success": False, "error": "CVE data is required", "_status_code": 400}

    cve_id = cve_data.get("id") or cve_data.get("cve_id")
    if not cve_id:
        return {"success": False, "error": "CVE ID is required in cve_data", "_status_code": 400}

    if not GEMINI_API_KEY:
        return {"success": False, "error": "Gemini API key not configured", "_status_code": 503}

    # Build a prompt that passes all available NVD facts to Gemini so it
    # explains the data rather than independently hallucinating details.
    description = cve_data.get("description", "Not available")
    cvss_score = cve_data.get("cvss_score", "Unknown")
    severity = cve_data.get("severity", "Unknown")
    cvss_vector = cve_data.get("cvss_vector", "Unknown")
    cpe = cve_data.get("cpe", "Unknown")
    published = cve_data.get("published", "Unknown")
    last_modified = cve_data.get("last_modified", "Unknown")
    references = cve_data.get("references", [])
    affected_products = cve_data.get("affected_products", [])
    affected_versions = cve_data.get("affected_versions", [])

    refs_text = "\n".join(f"  - {r}" for r in references[:5]) if references else "  None provided"
    affected_text = ", ".join(affected_products) if affected_products else "See CPE above"
    versions_text = ", ".join(affected_versions) if affected_versions else "See NVD description"

    prompt = f"""You are a cybersecurity assistant explaining a known vulnerability to a normal user, beginner developer, student, or non-security expert. Use plain, conversational language.

CRITICAL RULES:
- Base your explanation ONLY on the NVD facts supplied below.
- Do NOT invent CVE IDs, CVSS scores, severity ratings, affected versions, or any technical facts.
- Do NOT state facts not supported by the supplied data. If not enough info, say "Information not available from the supplied vulnerability data."
- Do NOT claim that a system is vulnerable simply because a service is detected (use wording like "The detected version may be affected. Verify the exact installed package/version and configuration").
- Avoid unnecessary cybersecurity jargon. If a technical term is necessary, immediately explain it in simple language (e.g. instead of "Remote Code Execution (RCE)", say "An attacker may be able to make the affected system run commands of their choice.").
- Keep each answer to 2-4 plain sentences.
- Output ONLY the JSON object shown below — no markdown, no code fences, no extra text.

=== NVD FACTS (source of truth) ===
CVE ID: {cve_id}
NVD Description: {description}
CVSS Score: {cvss_score}
Severity: {severity}
CVSS Vector: {cvss_vector}
CPE (affected product): {cpe}
Affected Products: {affected_text}
Affected Versions: {versions_text}
Published: {published}
Last Modified: {last_modified}
NVD References:
{refs_text}
=== END NVD FACTS ===

Output this JSON object (fill every field, keep language simple):

{{
  "cve_id": "{cve_id}",
  "what_is_this": "Explain what went wrong in simple terms.",
  "why_should_i_care": "Explain the real-world risk without unnecessary technical terminology.",
  "what_could_happen": "Explain what an attacker could potentially do using simple language.",
  "am_i_affected": "Clearly explain which software/version/system is affected based ONLY on the supplied NVD data.",
  "what_should_i_do": "Give practical remediation guidance based on authoritative information.",
  "how_do_i_verify_the_fix": "Give simple verification guidance when supported by the available data."
}}"""

    # ── Attempt 1: google.genai SDK ──────────────────────────────────────────
    if genai_client:
        try:
            logger.info("Calling Gemini via google.genai SDK for CVE explanation: %s", cve_id)
            sdk_resp = genai_client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
            raw_text = getattr(sdk_resp, "text", None)
            if not raw_text:
                try:
                    resp_json = (
                        sdk_resp.to_dict()
                        if hasattr(sdk_resp, "to_dict")
                        else json.loads(json.dumps(sdk_resp, default=lambda o: getattr(o, "__dict__", str(o))))
                    )
                except Exception:
                    resp_json = str(sdk_resp)
                raw_text = _extract_gemini_text(resp_json) or json.dumps(resp_json)
            parsed = _parse_cve_explanation(raw_text, cve_id)
            return {"success": True, "data": parsed}
        except Exception as e:
            logger.error("google.genai SDK call failed for CVE explanation %s: %s", cve_id, e)

    # ── Attempt 2: REST fallback ─────────────────────────────────────────────
    try:
        logger.info("Sending request to Gemini REST for CVE explanation: %s", cve_id)
        resp = _call_gemini_rest(prompt)
        logger.info("Gemini response status: %s", resp.status_code)
        err = _handle_gemini_rest_errors(resp)
        if err:
            return err
        raw_text = _extract_gemini_text(resp.json()) or json.dumps(resp.json())
        parsed = _parse_cve_explanation(raw_text, cve_id)
        return {"success": True, "data": parsed}
    except requests.Timeout:
        return {"success": False, "error": "Gemini request timed out", "_status_code": 504}
    except requests.RequestException as e:
        return {"success": False, "error": "Network error when calling Gemini", "detail": str(e), "_status_code": 502}
    except Exception as e:
        logger.error("Unexpected error during CVE explanation %s: %s", cve_id, e)
        return {"success": False, "error": "Failed to generate CVE explanation", "detail": str(e), "_status_code": 500}


def _parse_cve_explanation(raw_text: str, cve_id: str) -> dict:
    """Extract the structured JSON explanation from Gemini's raw text output.

    Tries strict JSON parse first; if that fails, falls back to returning the
    raw text in the ``what_is_this`` field so the UI always has something to show.
    """
    if not raw_text:
        return {
            "cve_id": cve_id,
            "what_is_this": "AI did not return a response.",
            "why_should_i_care": "",
            "what_could_happen": "",
            "am_i_affected": "",
            "what_should_i_do": "",
            "how_do_i_verify_the_fix": "",
        }

    # Strip potential markdown code fences Gemini sometimes adds despite instructions
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        # Drop first line (```json or ```) and last line (```)
        cleaned = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:]).strip()

    try:
        data = json.loads(cleaned)
        # Normalise: ensure all expected keys are present
        expected_keys = ["cve_id", "what_is_this", "why_should_i_care", "what_could_happen",
                         "am_i_affected", "what_should_i_do", "how_do_i_verify_the_fix"]
        for key in expected_keys:
            if key not in data:
                data[key] = ""
        data["cve_id"] = cve_id  # Always use the authoritative ID
        return data
    except (json.JSONDecodeError, ValueError):
        logger.warning("Could not parse CVE explanation JSON for %s; returning raw text", cve_id)
        return {
            "cve_id": cve_id,
            "what_is_this": raw_text,
            "why_should_i_care": "",
            "what_could_happen": "",
            "am_i_affected": "",
            "what_should_i_do": "",
            "how_do_i_verify_the_fix": "",
        }
