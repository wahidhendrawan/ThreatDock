FROM node:26.13.0-alpine3.24@sha256:8996bb5821d62a8fd9bb27c1cb07462f3fdce6e47d640c6a881ead0b064ce216 AS build
WORKDIR /app

# Install production dependencies exactly as locked (dev tools such as sqlite3 are not needed at runtime)
COPY package*.json ./
RUN npm ci --omit=dev

# Copy source code
COPY . .

# Expose backend port
EXPOSE 5002

# Use node user for better security
RUN chown -R node:node /app
USER node

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD wget -qO /dev/null http://127.0.0.1:5002/healthz || exit 1

# Start the Express application (--no-warnings suppresses internal TimeoutOverflowWarning)
CMD ["node", "--no-warnings", "app.js"]
