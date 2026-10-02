FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /srv/hub

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app/ app/
COPY mcp_server/ mcp_server/
COPY static/ static/

RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin hub \
    && mkdir -p /data \
    && chown -R hub:hub /srv/hub /data

USER hub

ENV HUB_HOST=0.0.0.0 \
    HUB_PORT=8000 \
    HUB_DATA_DIR=/data \
    HUB_OLLAMA_URL=http://ollama:11434

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 \
    CMD python -c "import urllib.request as u, sys; sys.exit(0 if u.urlopen('http://127.0.0.1:8000/api/challenges', timeout=4).status == 200 else 1)"

CMD ["python", "-m", "app"]
