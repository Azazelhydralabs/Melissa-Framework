# Build wrapper verifies this local base ID and the final RootFS layer prefix:
# sha256:b8b264f0d1c889fe9510197a0b16a85d06685b2d112bb4115f7b33072ce46ec4
FROM melissa-code05-base:20261019
RUN rustup component add --toolchain 1.98.1 rustfmt clippy rust-analyzer rust-src
RUN apt-get update && apt-get install -y --no-install-recommends lldb-19 llvm-19 python3-venv xz-utils ca-certificates && rm -rf /var/lib/apt/lists/*
RUN curl --fail --location https://nodejs.org/dist/v24.22.0/node-v24.22.0-linux-x64.tar.xz --output /tmp/node.tar.xz && echo 'cc2f601cee82d9a5a233302fe307abc600727035fd7d2c3a3571755989e95008  /tmp/node.tar.xz' | sha256sum --check && mkdir -p /opt/node && tar -xJf /tmp/node.tar.xz --strip-components=1 -C /opt/node && rm /tmp/node.tar.xz
ENV PATH="/opt/node/bin:/opt/melissa-python/bin:/opt/melissa-tools/node_modules/.bin:${PATH}"
ENV NODE_PATH="/opt/melissa-tools/node_modules"
COPY requirements.lock /opt/requirements.lock
RUN python3 -m venv /opt/melissa-python && /opt/melissa-python/bin/python -m pip install --no-cache-dir --require-hashes --report /opt/pip-install-report.json -r /opt/requirements.lock
COPY package.json package-lock.json /opt/melissa-tools/
RUN cd /opt/melissa-tools && npm ci --ignore-scripts --no-audit --no-fund
RUN curl --fail --location https://github.com/microsoft/vscode-js-debug/releases/download/v1.140.0/js-debug-dap-v1.140.0.tar.gz --output /tmp/js-debug.tar.gz && echo '27dab92937ec1ab35821ae955aac867544fe06a1b6307229049f2d789af10968  /tmp/js-debug.tar.gz' | sha256sum --check && mkdir -p /opt/js-debug && tar -xzf /tmp/js-debug.tar.gz --strip-components=1 -C /opt/js-debug && rm /tmp/js-debug.tar.gz
RUN mkdir -p /opt/melissa-manifests && dpkg-query -W > /opt/melissa-manifests/dpkg.txt && cp /opt/melissa-tools/package-lock.json /opt/melissa-manifests/npm-lock.json && cp /opt/pip-install-report.json /opt/melissa-manifests/pip-install-report.json && rustc -Vv > /opt/melissa-manifests/rustc.txt && cargo clippy --version > /opt/melissa-manifests/clippy.txt && cargo fmt --version > /opt/melissa-manifests/rustfmt.txt && node --version > /opt/melissa-manifests/node.txt && python3 --version > /opt/melissa-manifests/python.txt
