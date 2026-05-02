import json
import uuid
from datetime import datetime
from pathlib import Path


SRC_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = SRC_DIR.parent
HISTORY_FILE = PROJECT_ROOT / "scan_history.json"
MESSAGES_FILE = PROJECT_ROOT / "messages.json"


def load_history():
    if not HISTORY_FILE.exists():
        return []

    try:
        with HISTORY_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
            return data if isinstance(data, list) else []
    except Exception as e:
        print(f"Error loading history: {e}")
        return []


def save_history(history):
    try:
        with HISTORY_FILE.open("w", encoding="utf-8") as file:
            json.dump(history, file, indent=4)
        print(f"File saved: {HISTORY_FILE}")
    except Exception as e:
        print(f"Error saving history: {e}")


def load_messages():
    if not MESSAGES_FILE.exists():
        return []

    try:
        with MESSAGES_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
            return data if isinstance(data, list) else []
    except Exception as e:
        print(f"Error loading messages: {e}")
        return []


def save_message(message_data):
    try:
        messages = load_messages()
        message_data["id"] = str(uuid.uuid4())
        message_data["timestamp"] = datetime.now().isoformat()
        messages.insert(0, message_data)
        with MESSAGES_FILE.open("w", encoding="utf-8") as file:
            json.dump(messages, file, indent=4)
        return True
    except Exception as e:
        print(f"Error saving message: {e}")
        return False
