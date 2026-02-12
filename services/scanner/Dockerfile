FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY config.py scans.py main.py ./

ENTRYPOINT ["python", "-u", "main.py"]
