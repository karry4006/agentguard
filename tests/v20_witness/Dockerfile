FROM python:3.13-slim
WORKDIR /witness
RUN python -m pip install --no-cache-dir fastapi uvicorn cryptography
COPY app.py .
RUN mkdir /data && chown 65532:65532 /data
USER 65532:65532
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
