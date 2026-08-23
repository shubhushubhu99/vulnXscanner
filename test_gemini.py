import os
import sys
from dotenv import load_dotenv

# Add src to path so we can import project modules if needed
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

# Load environment variables from .env
load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    print("❌ Error: GEMINI_API_KEY is not set in .env file")
    sys.exit(1)

print(f"✅ Found GEMINI_API_KEY: {api_key[:5]}...{api_key[-4:] if len(api_key) > 9 else ''}")

try:
    from google import genai
    client = genai.Client(api_key=api_key)
    print("✅ Successfully initialized google.genai client")
    
    print("Sending test prompt to Gemini (gemini-3.6-flash)...")
    response = client.models.generate_content(
        model='gemini-3.6-flash',
        contents='Respond with a short greeting and tell me you are ready.'
    )
    
    print("\n--- Gemini Response ---")
    print(response.text)
    print("-----------------------")
    print("\n✅ API connection successful!")
    
except ImportError:
    print("⚠️ google.genai SDK not found, falling back to REST API test...")
    import requests
    
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent"
    params = {"key": api_key}
    headers = {"Content-Type": "application/json"}
    payload = {"contents": [{"parts": [{"text": "Respond with a short greeting and tell me you are ready."}]}]}
    
    print("Sending test prompt to Gemini REST API...")
    try:
        resp = requests.post(url, headers=headers, params=params, json=payload, timeout=10)
        if resp.status_code == 200:
            print("\n--- Gemini Response ---")
            try:
                text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
                print(text)
            except Exception as e:
                print(f"Raw response: {resp.json()}")
            print("-----------------------")
            print("\n✅ API connection successful!")
        else:
            print(f"❌ API Error {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"❌ Network error: {e}")
except Exception as e:
    print(f"❌ Error during API call: {e}")
