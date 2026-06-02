FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn[standard] pyyaml

COPY server.py .

EXPOSE 8081

HEALTHCHECK --interval=3s --timeout=5s --retries=15 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8081/health', timeout=3)" \
    || exit 1

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8081", "--log-level", "warning"]
