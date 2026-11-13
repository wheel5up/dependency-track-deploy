FROM public.ecr.aws/lambda/python:3.12

# Pin to a specific released tag for reproducible builds -- matches
# dependency-track-syft-scanner/scanner/Dockerfile's own pattern. Check
# https://github.com/anchore/syft/releases for newer versions.
ARG SYFT_VERSION=v1.18.0

RUN dnf install -y tar gzip && \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
      | sh -s -- -b /usr/local/bin "${SYFT_VERSION}" && \
    dnf clean all

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ${LAMBDA_TASK_ROOT}

CMD ["app.lambda_handler"]
