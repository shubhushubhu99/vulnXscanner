FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Set working directory to src for proper module imports
WORKDIR /app/src

CMD ["gunicorn", "--chdir", "/app/src", "app:app", "--bind", "0.0.0.0:8000"]
