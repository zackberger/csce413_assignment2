FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY knock_server.py knock_client.py protected_service.py ./

CMD ["bash", "-lc", "python3 -u protected_service.py & python3 -u knock_server.py"]
