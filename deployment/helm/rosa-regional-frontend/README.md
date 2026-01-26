# rosa-regional-frontend Helm Chart

This Helm chart deploys the rosa-regional-frontend API with an Envoy sidecar proxy on Kubernetes.

## Prerequisites

- Amazon EKS cluster with Auto Mode enabled
- Kubernetes 1.19+
- Helm 3.2.0+
- A ConfigMap named `bootstrap-output` in the `kube-system` namespace containing the `api_target_group_arn` key

**Note:** This chart uses the `eks.amazonaws.com/v1` TargetGroupBinding API, which is natively supported in EKS Auto Mode. No additional AWS Load Balancer Controller installation is required.

## Installation

### Install the chart

```bash
helm install rosa-regional-frontend ./deployment/helm/rosa-regional-frontend \
  --namespace rosa-regional-frontend \
  --create-namespace
```

### Install with custom values

```bash
helm install rosa-regional-frontend ./deployment/helm/rosa-regional-frontend \
  --namespace rosa-regional-frontend \
  --create-namespace \
  --values custom-values.yaml
```

## Upgrading

```bash
helm upgrade rosa-regional-frontend ./deployment/helm/rosa-regional-frontend \
  --namespace rosa-regional-frontend
```

## Uninstalling

```bash
helm uninstall rosa-regional-frontend --namespace rosa-regional-frontend
```

## Configuration

The following table lists the configurable parameters of the chart and their default values.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `namespace` | Namespace to deploy into | `rosa-regional-frontend` |
| `app.name` | Application name | `rosa-regional-frontend` |
| `app.image.repository` | Application image repository | `quay.io/cdoan0/rosa-regional-frontend-api` |
| `app.image.tag` | Application image tag | `latest` |
| `app.image.pullPolicy` | Image pull policy | `Always` |
| `app.args.logLevel` | Application log level | `info` |
| `app.args.maestroUrl` | Maestro service URL | `http://maestro:8000` |
| `app.args.dynamodbRegion` | DynamoDB region | `us-east-2` |
| `app.args.dynamodbTable` | DynamoDB table name | `rosa-customer-accounts` |
| `deployment.replicas` | Number of replicas | `1` |
| `targetGroup.lookup.enabled` | Enable ConfigMap lookup for Target Group ARN | `true` |
| `targetGroup.lookup.namespace` | Namespace containing the ConfigMap | `kube-system` |
| `targetGroup.lookup.configMapName` | ConfigMap name | `bootstrap-output` |
| `targetGroup.lookup.key` | Key in ConfigMap containing ARN | `api_target_group_arn` |
| `targetGroup.arn` | Manual Target Group ARN (if lookup disabled) | `""` |

## Target Group ARN Configuration

The chart supports two methods for configuring the AWS Target Group ARN:

### Method 1: ConfigMap Lookup (Default)

The chart will automatically lookup the Target Group ARN from a ConfigMap using Helm's `lookup` function:

```yaml
targetGroup:
  lookup:
    enabled: true
    namespace: kube-system
    configMapName: bootstrap-output
    key: api_target_group_arn
```

**Note:** The ConfigMap must exist before installing the chart, or the TargetGroupBinding will have an empty ARN.

### Method 2: Manual Configuration

You can disable lookup and manually specify the ARN:

```yaml
targetGroup:
  lookup:
    enabled: false
  arn: "arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/my-target-group/50dc6c495c0c9188"
```

## Architecture

This deployment uses an Envoy sidecar proxy to consolidate all external traffic through port 8080, which then routes to the application's different internal ports:

- `/api/*` → Port 8000 (API endpoints)
- `/v0/live`, `/v0/ready` → Port 8081 (Health checks)
- `/metrics` → Port 9090 (Prometheus metrics)
- `/` (default) → Port 8000 (API)

### Traffic Flow

```
AWS ALB → Service (8080) → Envoy (8080) → Application (8000/8081/9090)
```

### Health Checks

- **Kubernetes Probes**: Check the application directly on port 8081 (not through Envoy)
- **ALB Health Checks**: Go through Envoy on port 8080

## Example Custom Values

```yaml
deployment:
  replicas: 3

app:
  image:
    tag: v1.2.3
  args:
    logLevel: debug
    dynamodbRegion: us-west-2
  resources:
    requests:
      cpu: 200m
      memory: 256Mi
    limits:
      cpu: 1000m
      memory: 1Gi

targetGroup:
  lookup:
    enabled: true
```

## Testing

Verify the installation:

```bash
# Check pods
kubectl get pods -n rosa-regional-frontend

# Check service
kubectl get svc -n rosa-regional-frontend

# Check target group binding
kubectl get targetgroupbinding -n rosa-regional-frontend

# Test health endpoint through the service
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://rosa-regional-frontend.rosa-regional-frontend.svc.cluster.local:8080/v0/live
```
