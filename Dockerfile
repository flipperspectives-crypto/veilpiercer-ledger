FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# OpenTimestamps client - optional but enables real Bitcoin anchoring
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -sL https://raw.githubusercontent.com/opentimestamps/opentimestamps-client/master/ots.py -o /usr/local/bin/ots \
    && chmod +x /usr/local/bin/ots || true
COPY . .
EXPOSE 9100
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "9100"]
