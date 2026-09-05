# Architecture: Home Assistant builds this image from the add-on base and runs
# server.js as the local HTTP/WebSocket bridge. It is not the platform runtime.
ARG BUILD_FROM=ghcr.io/hassio-addons/base:14.0.6
FROM ${BUILD_FROM}

RUN apk add --no-cache nodejs npm

WORKDIR /opt/dinodia-hub-agent

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev

COPY server.js ./
COPY electricUsageTracker.js ./
COPY rootfs/ /

RUN chmod +x /etc/services.d/dinodia-hub-agent/run

EXPOSE 8099
