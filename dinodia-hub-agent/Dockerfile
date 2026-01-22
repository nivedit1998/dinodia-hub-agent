ARG BUILD_FROM=ghcr.io/hassio-addons/base:14.0.6
FROM ${BUILD_FROM}

RUN apk add --no-cache nodejs npm

WORKDIR /opt/dinodia-hub-agent

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev

COPY server.js ./
COPY rootfs/ /

RUN chmod +x /etc/services.d/dinodia-hub-agent/run

EXPOSE 8099
