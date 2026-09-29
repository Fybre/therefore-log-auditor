FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY auditor ./auditor
RUN pip install --no-cache-dir .
COPY config/rules.yaml ./config/rules.yaml
ENV AUDITOR_TENANTS_FILE=/app/config/tenants.yaml \
    AUDITOR_RULES_FILE=/app/config/rules.yaml \
    AUDITOR_REPORTS_DIR=/app/reports \
    AUDITOR_ENV_FILE=/nonexistent
ENTRYPOINT ["auditor"]
CMD ["serve"]
