# ROSA Regional Frontend API

Stateless gateway API for ROSA HCP regional cluster management.

## Architecture

```mermaid
flowchart TB
    CLI["AWS CLI / SDK"] --> APIGW["API Gateway"]
    APIGW -->|SigV4 headers| AuthMW["Auth Middleware"]
    AuthMW -->|lookup| DDB[("DynamoDB")]
    AuthMW -->|privileged?| PrivCheck{"privileged"}

    PrivCheck -->|yes| MgmtHandler["management_clusters"]
    PrivCheck -->|no| Forbidden["403 Forbidden"]

    MgmtHandler -->|REST| Maestro["Maestro API"]
```

## Endpoints

| Endpoint                               | Auth       | Description                                  |
| -------------------------------------- | ---------- | -------------------------------------------- |
| `POST /api/v0/management_clusters`     | privileged | Create management cluster (Maestro consumer) |
| `GET /api/v0/management_clusters`      | privileged | List management clusters                     |
| `GET /api/v0/management_clusters/{id}` | privileged | Get management cluster                       |

## Configuration

| Flag                | Default                  | Description     |
| ------------------- | ------------------------ | --------------- |
| `--api-port`        | 8000                     | API server port |
| `--maestro-url`     | `http://maestro:8000`    | Maestro API URL |
| `--dynamodb-table`  | `rosa-customer-accounts` | DynamoDB table  |
| `--dynamodb-region` | `us-east-1`              | AWS region      |

## Build

```bash
make build
make test
make image
```
