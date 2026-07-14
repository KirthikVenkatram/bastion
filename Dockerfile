FROM python:3.11-slim

# Bundle OPA into the same image — no separate hosted OPA service.
RUN apt-get update && apt-get install -y curl && \
    curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64 && \
    chmod +x /usr/local/bin/opa && \
    apt-get remove -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["uvicorn", "app.github_app.webhook:app", "--host", "0.0.0.0", "--port", "8000"]
