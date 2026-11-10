FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY ml/models/headline_model_calibrated.joblib ./ml/models/headline_model_calibrated.joblib
COPY ml/models/headline_tfidf_transformer.joblib ./ml/models/headline_tfidf_transformer.joblib
COPY frozen_config.json ./frozen_config.json
COPY docs/results ./docs/results
COPY Decision_Log.md ./Decision_Log.md
COPY docker-entrypoint.sh ./docker-entrypoint.sh

RUN mkdir -p /data
EXPOSE 8000
ENTRYPOINT ["sh", "./docker-entrypoint.sh"]
