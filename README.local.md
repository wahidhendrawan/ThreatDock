# ThreatDock: Local Development Setup

All P0, P1, and P2 tasks are complete. All pull requests are merged, and the `main` branch is stable.

This document provides instructions for running the full ThreatDock stack (frontend, backend, database, cache) on your local machine using Docker Compose.

## Prerequisites

1.  **Git:** You must have Git installed to clone the repository.
2.  **Docker Desktop:** You need Docker Desktop to run the containerized application stack. The application cannot run directly on the host OS without manual setup of PostgreSQL, Redis, and Node.js.

## Setup Instructions

1.  **Start Docker Desktop:**
    Before running any commands, ensure Docker Desktop is running on your machine.

2.  **Clone the Repository (if you haven't already):**
    ```bash
    git clone https://github.com/wahidhendrawan/ThreatDock.git
    cd ThreatDock
    ```

3.  **Create the Environment File:**
    The application uses a `.env` file at the root of the project to configure database credentials. A script is provided to generate this securely from the backend's example file.

    Run this command in your terminal at the root of the `ThreatDock` directory:
    ```bash
    if [ -e .env ]; then echo 'Root .env already exists; not modifying it.'; else set -a; source backend/.env.example; set +a; umask 077; printf 'POSTGRES_DB=%s\nPOSTGRES_USER=%s\nPOSTGRES_PASSWORD=%s\n' "${PGDATABASE:-threatdock}" "${PGUSER:-threatdock}" "${PGPASSWORD:?backend/.env.example must define PGPASSWORD}" > .env; echo 'Created root .env from backend database settings (permissions 600).'; fi
    ```
    This creates a `.env` file with the necessary `POSTGRES_*` variables.

4.  **Build and Run the Application:**
    With Docker running and the `.env` file in place, start the entire stack:
    ```bash
    docker compose up --build -d
    ```
    This command will build the container images and start the services in the background.

5.  **Verify Services are Running:**
    Check the logs to ensure all services started correctly.
    ```bash
    docker compose logs -f backend
    docker compose logs -f frontend
    ```
    Look for a "ready" message from the backend and a successful compile message from the frontend. Press `Ctrl+C` to exit the logs.

## Accessing the Application

Once the stack is running, you can access the different components:

*   **Frontend Application:** [http://localhost:3000](http://localhost:3000)
*   **Backend Health Check:** [http://localhost:5002/healthz](http://localhost:5002/healthz)
*   **Backend Readiness Check:** [http://localhost:5002/readyz](http://localhost:5002/readyz)
*   **API Documentation (Swagger UI):** [http://localhost:3000/api/docs](http://localhost:3000/api/docs)
*   **Prometheus Metrics:** [http://localhost:5002/metrics](http://localhost:5002/metrics)

## Stopping the Application

To stop all running services, use the following command:
```bash
docker compose down
```

This concludes all assigned tasks. The repository is fully updated and ready for local execution.
