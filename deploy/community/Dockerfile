# This argument deliberately has no default. Use preflight.py build so the
# Python base is validated as an exact repository[:tag]@sha256 reference first.
ARG SOVA_PYTHON_IMAGE
FROM ${SOVA_PYTHON_IMAGE}

ARG SOVA_WHEEL

LABEL org.opencontainers.image.title="SOVA OSS community registry"
LABEL org.opencontainers.image.description="Pre-alpha SOVA community registry runtime"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/TRUSCOR/SOVA-OSS"
LABEL org.opencontainers.image.vendor="SOVA OSS contributors"
LABEL org.sova.runtime.uid="65532"
LABEL org.sova.runtime.gid="65532"
LABEL org.sova.runtime.data="/var/lib/sova"
LABEL org.sova.runtime.operator="/run/sova/operator"

ENV HOME=/var/lib/sova \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY ${SOVA_WHEEL} /tmp/sova.whl

RUN python -m pip install --no-cache-dir /tmp/sova.whl \
    && rm -f /tmp/sova.whl \
    && install -d -o 65532 -g 65532 -m 0750 /var/lib/sova \
    && install -d -o 65532 -g 65532 -m 0750 /run/sova

USER 65532:65532
WORKDIR /var/lib/sova

ENTRYPOINT ["sova"]
CMD ["--help"]
