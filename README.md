# ROSA Regional Frontend API

Stateless gateway API for ROSA HCP regional cluster management.

## Architecture

```mermaid
flowchart TB
    subgraph Client
        CLI[AWS CLI / SDK]
    end

    subgraph API Gateway
        APIGW[API Gateway]
        APIGW -->|SigV4 validated| Headers[X-Amz-Account-Id<br/>X-Amz-Caller-Arn]
    end

    subgraph rosa-regional-frontend-api
        Headers --> AuthMW[DynamoDB Auth Middleware]
        AuthMW -->|account exists?| DDB[(DynamoDB<br/>rosa-customer-accounts)]
        AuthMW -->|privileged?| PrivCheck{privileged<br/>flag}

        PrivCheck -->|yes| MgmtHandler[/api/v0/management_clusters]
        PrivCheck -->|no| Forbidden[403 Forbidden]

        AuthMW -->|ToS only| ClusterHandler[/api/v0/clusters<br/>future]
    end

    subgraph Backend Services
        MgmtHandler -->|REST| Maestro[Maestro API<br/>/api/maestro/v1/consumers]
        ClusterHandler -->|REST/gRPC| HF[Hyperfleet API]
    end

    CLI --> APIGW
```

## Endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /api/v0/management_clusters` | privileged | Create management cluster (Maestro consumer) |
| `GET /api/v0/management_clusters` | privileged | List management clusters |
| `GET /api/v0/management_clusters/{id}` | privileged | Get management cluster |

## Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--api-port` | 8000 | API server port |
| `--maestro-url` | `http://maestro:8000` | Maestro API URL |
| `--dynamodb-table` | `rosa-customer-accounts` | DynamoDB table |
| `--dynamodb-region` | `us-east-1` | AWS region |

## Build

```bash
make build
make test
make image
```
