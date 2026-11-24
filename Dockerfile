FROM python:3.11-slim-bookworm AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.11-slim-bookworm AS runtime

WORKDIR /app
RUN groupadd -r specter && useradd -r -g specter -u 10002 specter \
    && mkdir -p /app/reports && chown -R specter:specter /app

COPY --from=builder /root/.local /home/specter/.local
ENV PATH=/home/specter/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1

COPY --chown=specter:specter spectergraph/ /app/spectergraph/
COPY --chown=specter:specter config/ /app/config/

USER specter

ENTRYPOINT ["python3", "-m", "spectergraph.cli"]
CMD ["--help"]
