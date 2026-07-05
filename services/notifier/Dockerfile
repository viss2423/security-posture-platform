FROM python:3.11-slim
WORKDIR /app
COPY services/notifier/requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY services/shared/ /app/shared/
RUN pip install --no-cache-dir /app/shared/secplat_telemetry
COPY services/notifier/main.py /app/main.py
CMD ["python", "main.py"]
