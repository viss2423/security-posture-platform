FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml /app/pyproject.toml

RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir .

COPY app /app/app
COPY tests /app/tests
COPY scripts /app/scripts
COPY models /app/models
COPY exports /app/exports

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host=0.0.0.0", "--port=8000"]
