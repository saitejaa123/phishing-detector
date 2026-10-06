FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --prefer-binary --no-cache-dir -r requirements.txt

# Copy all project files
COPY . .

# Train models at build time
RUN python train.py

# Expose port
EXPOSE 7860

# Start the app (HuggingFace uses port 7860)
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:7860", "--timeout", "180", "--workers", "1"]
