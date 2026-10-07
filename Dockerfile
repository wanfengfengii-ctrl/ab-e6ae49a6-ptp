FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

# Install runtime + verification dependencies (the same image is used by the
# one-shot "verify" service that runs tests and the API smoke check).
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY app ./app
COPY tests ./tests
COPY ptpbuild.py ./ptpbuild.py
COPY scripts ./scripts

EXPOSE 8000

# Container-local health check; compose gates the verify service on it.
HEALTHCHECK --interval=2s --timeout=2s --start-period=5s --retries=15 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
