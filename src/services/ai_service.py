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
