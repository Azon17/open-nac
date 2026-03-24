FROM python:3.12-slim
WORKDIR /app
RUN pip install fastapi uvicorn --no-cache-dir
RUN printf 'from fastapi import FastAPI\napp=FastAPI()\n@app.get("/health")\ndef h(): return {"status":"ok"}' > main.py
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
