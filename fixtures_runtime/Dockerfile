FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.12.19 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_LINK_MODE=copy
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable
COPY scripts/build_runtime.py /build_runtime.py
RUN python /build_runtime.py && rm /runtime/usr/local/bin/uv && \
    mkdir -p /runtime/data /runtime/seed /runtime/tmp /runtime/etc && \
    chmod 1777 /runtime/tmp && chown 10001:10001 /runtime/data /runtime/seed && \
    printf 'fixtures:x:10001:10001::/data:/nonexistent\n' > /runtime/etc/passwd && \
    printf 'fixtures:x:10001:\n' > /runtime/etc/group

# The official python:3.12-slim interpreter, stdlib, ELF dependencies and locked
# runtime packages only; avoid carrying the Debian package-management layer.
FROM scratch
COPY --from=builder /runtime /
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/app/.venv/bin:/usr/local/bin" HOME=/nonexistent
WORKDIR /app
USER 10001:10001
EXPOSE 80 8080 9090
ENTRYPOINT ["fixtures"]
CMD ["--help"]
