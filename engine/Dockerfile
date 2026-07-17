# Furix engine + FastAPI server (CPU). Build context = ./engine.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

# System libs some wheels need (psycopg2-binary is self-contained; pdfplumber
# pulls pillow which needs libjpeg/zlib at runtime for some ops).
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpq5 curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1) CPU-only torch first (avoids CUDA wheels), then the rest.
COPY requirements-engine.txt .
RUN pip install --index-url https://download.pytorch.org/whl/cpu torch>=2.2 \
 && pip install -r requirements-engine.txt

# 2) Engine code (flat imports resolve from /app; the API is /app/api).
COPY . /app

# Model + report-store locations (mounted volumes in compose).
ENV FURIX_DEVICE=cpu \
    HF_HOME=/models \
    FURIX_REPORT_STORE=/data/reports

EXPOSE 8000
# Lazy model load: the app starts fast; the first ingest warms SecureBERT.
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
