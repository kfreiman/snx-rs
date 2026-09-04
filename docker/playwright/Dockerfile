ARG PLAYWRIGHT_BASE_IMAGE=mcr.microsoft.com/playwright:v1.52.0-noble
FROM ${PLAYWRIGHT_BASE_IMAGE}

ARG PLAYWRIGHT_VERSION=1.52.0
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

WORKDIR /opt/snx-rs-playwright
RUN npm install --no-audit --no-fund --prefix /opt/snx-rs-playwright "playwright@${PLAYWRIGHT_VERSION}"

COPY auth.js /opt/snx-rs-playwright/auth.js

ENTRYPOINT ["node", "/opt/snx-rs-playwright/auth.js"]
