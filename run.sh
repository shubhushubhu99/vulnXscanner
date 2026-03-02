#!/bin/bash

# VulnX Security Scanner - Startup Script

echo "🚀 Starting VulnX Security Scanner..."
echo ""

# Activate virtual environment
source venv/bin/activate

# Check if Python dependencies are installed
echo "📦 Checking dependencies..."
pip list | grep -q "Flask==" && echo "✓ Flask found" || (echo "Installing dependencies..." && pip install -r requirements.txt)

# Set Flask environment
export FLASK_APP=src/app.py
export FLASK_ENV=development

# Change to src directory and run
cd src
echo "🚀 Starting Flask-SocketIO server..."
echo "📍 Open http://localhost:5000 in your browser"
echo ""
python app.py
