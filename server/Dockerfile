FROM python:3.13-slim-trixie AS build

WORKDIR /build
COPY requirements.lock ./requirements.lock
RUN python -m pip install --no-cache-dir --target /opt/site --requirement ./requirements.lock

COPY VERSION /opt/app/VERSION
COPY server/pyproject.toml /opt/app/server/pyproject.toml
COPY server/README.md /opt/app/server/README.md
COPY server/src /opt/app/server/src
COPY sdk/python/pyproject.toml /opt/app/sdk/python/pyproject.toml
COPY sdk/python/README.md /opt/app/sdk/python/README.md
COPY sdk/python/src /opt/app/sdk/python/src
COPY server/alembic.ini /opt/app/alembic.ini
COPY server/alembic /opt/app/alembic
COPY server/src /opt/app/src
COPY sdk/python/src /opt/app/sdk/python/src

# Install first-party metadata from the declared project versions. This keeps
# clean-clone image builds and generated SBOMs aligned with VERSION.
RUN python -m pip install --no-cache-dir --no-deps --target /opt/site /opt/app/server /opt/app/sdk/python

# Google Distroless Python Debian 13, nonroot. Keep this digest pinned.
FROM gcr.io/distroless/python3-debian13:nonroot@sha256:f3d5ddc6c64a019fe520e7f005f2880be21e6afc461b10a3c15ef2e4edc71e33

WORKDIR /app
COPY --from=build /opt/site /opt/site
COPY --from=build /opt/app /app

ENV PYTHONPATH=/app/src:/app/sdk/python/src:/opt/site \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 65532:65532
EXPOSE 8000

# Vector form is intentional: the final image has no shell or package manager.
CMD ["-m", "uvicorn", "agentguard_server.main:app", "--host", "0.0.0.0", "--port", "8000"]
