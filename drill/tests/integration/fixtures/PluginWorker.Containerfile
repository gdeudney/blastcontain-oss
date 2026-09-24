ARG BASE_IMAGE
FROM ${BASE_IMAGE}
COPY drill/tests/integration/fixtures/plugin_worker.py /opt/plugin/worker.py
