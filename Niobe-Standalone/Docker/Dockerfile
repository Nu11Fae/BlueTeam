FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl unzip git gnupg fonts-dejavu-core libcairo2 libffi8 libgdk-pixbuf-2.0-0 \
        libpango-1.0-0 libpangocairo-1.0-0 libharfbuzz0b libharfbuzz-subset0 libjpeg62-turbo \
        shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY niobe/ niobe/
COPY scripts/ scripts/
COPY ops/ ops/

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

EXPOSE 8080

CMD ["uvicorn", "niobe.control_plane:app", "--host", "0.0.0.0", "--port", "8080"]
