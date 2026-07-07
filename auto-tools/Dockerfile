FROM golang:1.22-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH=/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv ca-certificates curl git jq \
    && rm -rf /var/lib/apt/lists/*

RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

COPY requirements.txt /app/requirements.txt
RUN pip3 install --break-system-packages --no-cache-dir -r /app/requirements.txt

COPY runner.py /app/runner.py

RUN mkdir -p /data/auto-tools /data/auto-tools/runs

EXPOSE 8770

CMD ["uvicorn", "runner:app", "--host", "0.0.0.0", "--port", "8770"]
