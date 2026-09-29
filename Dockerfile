FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Set your seed with -e FLAG_SEED=<your FHSU username>. If unset, `docker run`
# starts with a warning banner and a default seed; `docker compose` refuses to start.
# HOST=0.0.0.0 is needed inside the container; publish the port on
# 127.0.0.1 only (see docker-compose.yml / README).
ENV HOST=0.0.0.0
ENV PORT=5000
EXPOSE 5000

CMD ["python", "app.py"]
