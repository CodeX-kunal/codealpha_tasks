FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY scripts ./scripts
COPY wsgi.py .
RUN useradd -r -u 10001 appuser && mkdir /data && chown appuser /data
USER appuser
ENV DB_PATH=/data/secure_app.db TRUST_PROXY=1
VOLUME /data
EXPOSE 8000
# 1 worker + threads: tiny memory footprint, and the in-memory rate limiter stays consistent
CMD ["gunicorn", "-b", "0.0.0.0:8000", "-w", "1", "--threads", "8", "wsgi:app"]
