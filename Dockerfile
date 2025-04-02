FROM python:3.9-slim
LABEL authors="DimaK"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY gen_ca.sh .
COPY gen_cert.sh .
RUN chmod +x gen_ca.sh gen_cert.sh

RUN pip install pyOpenSSL

EXPOSE 8080 8000

COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
