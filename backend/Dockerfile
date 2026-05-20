FROM node:25.8.0-trixie-slim AS build
WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install

# Copy source code
COPY . .

# Expose backend port
EXPOSE 5002

# Use node user for better security
RUN chown -R node:node /app
USER node

# Start the Express application
CMD ["npm", "start"]