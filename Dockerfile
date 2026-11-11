FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src
WORKDIR /app
RUN mkdir /state && chown 1000:1000 /state
COPY src /app/src
USER 1000:1000
ENTRYPOINT ["python", "-m", "ssrsf.prototype.service"]
