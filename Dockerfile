# Host-agnostic image for the Enclave demo server (dashboard + upload endpoint).
# Deploys identically to AWS App Runner / ECS, Hugging Face Spaces (Docker), Render or Railway.
# The core product runs on-premises; this image only exists so an evaluator can try it in a browser.
FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for layer caching.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Runtime assets: example config and the offline intel bundle (hash-verified on load).
COPY config ./config
COPY intel ./intel

# Statistical detectors only in the public demo (the supervised model needs a CIC-IDS2017 artifact
# and traffic from its own distribution; enabling it here would mis-fire on the synthetic sample).
ENV PORT=8000
EXPOSE 8000

# Shell form so ${PORT} (set by Render/Railway/App Runner) is honoured; defaults to 8000.
CMD enclave serve --config config/enclave.example.json --host 0.0.0.0 --port ${PORT:-8000}
