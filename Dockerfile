ARG BASE_IMAGE=python:3.11-slim
FROM ${BASE_IMAGE}
WORKDIR /app
COPY requirements.txt .
ARG PIP_INDEX=
RUN pip install --no-cache-dir -r requirements.txt ${PIP_INDEX}
COPY app.py .
COPY static ./static
EXPOSE 80
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "80"]
