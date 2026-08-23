import os
import logging
from dotenv import load_dotenv
from flask_socketio import SocketIO

# Try importing Gemini SDK
try:
    from google import genai
except Exception:
    genai = None

# Load environment variables (GEMINI_API_KEY should be in .env)
load_dotenv()

# Gemini API key (may be absent in some environments)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_OAUTH_TOKEN = os.getenv("GEMINI_OAUTH_TOKEN")
# Optional explicit auth type: 'api_key' or 'bearer'. If unset, we auto-detect.
GEMINI_AUTH_TYPE = os.getenv("GEMINI_AUTH_TYPE")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")



# LOGGING
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulnx.gemini")

if not GEMINI_API_KEY:
    logger.warning("GEMINI_API_KEY not set; AI features will fail.")


genai_client = None

if GEMINI_API_KEY and genai is not None:
    try:
        if GEMINI_AUTH_TYPE != 'bearer':
            genai_client = genai.Client(api_key=GEMINI_API_KEY)
            logger.info("Initialized google.genai client")
    except Exception as e:
        logger.warning(f"Gemini client init failed: {e}")

# Use threading mode for broad compatibility
# Configure with longer timeouts and ping/pong to keep connection alive during long scans
socketio = SocketIO(
    cors_allowed_origins="*",
    async_mode='threading',
    ping_timeout=120,
    ping_interval=30,
    engineio_logger=True,
    socketio_logger=True
)

# Global storage for state
latest_results = {
    'results': None,
    'target': '',
    'deep_scan': False
}