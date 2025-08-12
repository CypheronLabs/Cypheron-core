# Cypheron-core API Route Guide

## Introduction

This document provides a reference for the available API endpoints in the Cypheron-core service. It is intended for developers integrating front-end or other backend services with this API.

## Authentication

The API exposes routes with three different authentication levels:

1.  **Public:** No authentication is required. These are typically for status or health checks.
2.  **Standard API Key:** Requires a valid API key to be sent in the request headers. This is the standard authentication method for most API calls.
3.  **Demo JWT:** A separate set of routes that accept a short-lived JSON Web Token (JWT) for demonstration purposes. These routes mirror the standard API but use a different authentication middleware.

An API key can be provided in one of two ways:
-   **Header:** `x-api-key: <YOUR_API_KEY>`
-   **Bearer Token:** `Authorization: Bearer <YOUR_API_KEY>`

## API Endpoints

### Public Routes

| Method | Path                           | Description                                      |
| :----- | :----------------------------- | :----------------------------------------------- |
| `GET`  | `/health`                      | Performs a basic health check of the service.    |
| `GET`  | `/health/detailed`             | Provides a detailed health report.               |
| `GET`  | `/health/ready`                | Performs a readiness check.                      |
| `GET`  | `/health/live`                 | Performs a liveness check.                       |
| `GET`  | `/public/status`               | Returns the public operational status of the API.|
| `GET`  | `/status`                      | Serves a static HTML status page.                |
| `GET`  | `/static/{*path}`              | Serves static assets for the status page.        |

### Authenticated Routes (Standard API Key or Demo JWT)

These endpoints are the core of the service and are accessible via a standard API key or a demo JWT. The same paths are used for both authentication types, but they are handled by different middleware stacks based on the server's configuration.

#### Key Encapsulation Mechanism (KEM)

| Method | Path                        | Description                                         |
| :----- | :-------------------------- | :-------------------------------------------------- |
| `POST` | `/kem/{variant}/keygen`     | Generates a new public/private key pair.            |
| `POST` | `/kem/{variant}/encapsulate`| Creates and encapsulates a shared secret.           |
| `POST` | `/kem/{variant}/decapsulate`| Decapsulates a shared secret.                       |
| `GET`  | `/kem/{variant}/info`       | Returns information about a specific KEM variant.   |

#### Digital Signatures (SIG)

| Method | Path                     | Description                                      |
| :----- | :----------------------- | :----------------------------------------------- |
| `POST` | `/sig/{variant}/keygen`  | Generates a new signing/verification key pair.   |
| `POST` | `/sig/{variant}/sign`    | Signs a message digest with a private key.       |
| `POST` | `/sig/{variant}/verify`  | Verifies a signature against a message digest.   |

#### Hybrid Encryption

| Method | Path            | Description                                      |
| :----- | :-------------- | :----------------------------------------------- |
| `POST` | `/hybrid/sign`  | Creates a hybrid-signed JWT.                     |

#### NIST Compliance

| Method | Path                 | Description                                      |
| :----- | :------------------- | :----------------------------------------------- |
| `GET`  | `/nist/compliance`   | Provides information on NIST compliance status.  |
| `GET`  | `/nist/deprecation`  | Provides warnings about deprecated algorithms.   |

#### Monitoring

| Method | Path                                      | Description                                      |
| :----- | :---------------------------------------- | :----------------------------------------------- |
| `GET`  | `/monitoring`                             | Returns the general monitoring status.           |
| `GET`  | `/monitoring/dashboard`                   | Returns data for the monitoring dashboard.       |
| `GET`  | `/monitoring/metrics/summary`             | Returns a summary of all metrics.                |
| `GET`  | `/monitoring/alerts`                      | Retrieves a list of current alerts.              |
| `POST` | `/monitoring/alerts/check`                | Manually triggers an alert check.                |
| `POST` | `/monitoring/alerts/{alert_id}/acknowledge` | Acknowledges a specific alert.                   |
| `GET`  | `/monitoring/security/events`             | Retrieves a list of security events.             |
| `GET`  | `/monitoring/compliance/report`           | Retrieves the latest compliance report.          |
