FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY worker.py /app/worker.py
CMD ["python", "worker.py"]

