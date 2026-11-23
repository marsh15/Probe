FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/refserver \
    PATH=/opt/refserver/bin:$PATH

# git backs the git_log tool and the seeded demo repository.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY pyproject.toml uv.lock ./
COPY src ./src
RUN pip install "uv>=0.5" \
    && uv sync --frozen --no-dev --no-editable \
    && pip uninstall -y uv

RUN useradd --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin refserver \
    && refserver seed --out /data --seed 1 \
    && chown -R 10001:10001 /data

USER 10001
WORKDIR /data
EXPOSE 3000
ENTRYPOINT ["refserver"]
CMD ["stdio"]
