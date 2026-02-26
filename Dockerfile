FROM python:3.12-slim

WORKDIR /app

COPY . .
RUN pip install --no-cache-dir .

EXPOSE 8000

ENV MCP_HOST=0.0.0.0
CMD ["python", "server.py"]
