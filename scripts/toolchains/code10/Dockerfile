# Exact CODE-06 image; the builder verifies the inherited RootFS prefix.
FROM melissa-code06-complete:20261020
COPY package.json package-lock.json /opt/melissa-web-tools/
RUN cd /opt/melissa-web-tools && /opt/node/bin/npm ci --ignore-scripts --no-audit --no-fund
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/melissa-browsers
RUN /opt/node/bin/node /opt/melissa-web-tools/node_modules/playwright/cli.js install --with-deps chromium
RUN apt-get update && apt-get install -y --no-install-recommends postgresql postgresql-client && rm -rf /var/lib/apt/lists/*
COPY requirements.lock /opt/melissa-code10-requirements.lock
RUN /opt/melissa-python/bin/python -m pip install --no-cache-dir --only-binary=:all: --require-hashes --no-deps -r /opt/melissa-code10-requirements.lock
RUN mkdir -p /opt/melissa-code10-manifests && dpkg-query -W > /opt/melissa-code10-manifests/dpkg.txt && cp /opt/melissa-web-tools/package-lock.json /opt/melissa-code10-manifests/npm-lock.json && /opt/node/bin/node /opt/melissa-web-tools/node_modules/playwright/cli.js --version > /opt/melissa-code10-manifests/playwright.txt && python3 -c 'import sqlite3; print(sqlite3.sqlite_version)' > /opt/melissa-code10-manifests/sqlite.txt && psql --version > /opt/melissa-code10-manifests/postgres.txt
