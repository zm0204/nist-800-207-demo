FROM python:3.12-slim
WORKDIR /demo
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY static ./static
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "app.dashboard:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
