FROM python:3.11-slim
WORKDIR /app
COPY services/worker-web/requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY services/shared/ /app/shared/
RUN pip install --no-cache-dir /app/shared/secplat_telemetry
COPY services/worker-web/worker.py /app/worker.py
CMD ["python", "worker.py"]
