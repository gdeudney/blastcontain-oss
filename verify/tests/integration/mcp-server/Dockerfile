FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn[standard]

COPY server.py .

EXPOSE 8080

HEALTHCHECK --interval=3s --timeout=5s --retries=15 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health', timeout=3)" \
    || exit 1

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "warning"]
