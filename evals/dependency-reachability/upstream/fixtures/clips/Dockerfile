FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install . python-multipart==0.0.32 uvicorn==0.49.0
CMD ["python", "-m", "uvicorn", "clips.api:gateway", "--host", "0.0.0.0"]
