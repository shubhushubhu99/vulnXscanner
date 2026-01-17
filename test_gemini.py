# test_gemini.py
# IMPORTANT: Replace YOUR_API_KEY_HERE with your real Gemini API key
#            Get it from: https://aistudio.google.com/app/apikey

from google import genai
import datetime

# === Hard-coded API key (only for testing - never commit this!) ===
MY_API_KEY = "AIzaSyB6j5p-pIsszCpLjTNk4nPBYq9BI2XIjpI"   # ←←← CHANGE THIS

# Create client
client = genai.Client(api_key=MY_API_KEY)

try:
    print("Trying to generate content with gemini-2.5-flash...\n")
    
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents="""Write exactly one sentence: "Hello from Gemini 2.5 Flash test - it works!" """
    )
    
    print("SUCCESS! Gemini responded:\n")
    print(response.text.strip())
    
    print("\nCurrent time:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

except Exception as e:
    import traceback
    print("ERROR OCCURRED:")
    print(str(e))
    traceback.print_exc()