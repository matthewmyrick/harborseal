# HarborSeal API Kubernetes Deployment

This directory contains Kubernetes manifests for deploying HarborSeal API with ArgoCD and GitHub Actions integration.

## Structure

```
kubernetes/
├── base/                          # Base Kubernetes resources
│   ├── kustomization.yaml
│   ├── namespace.yaml
│   ├── mongodb-deployment.yaml
│   ├── mongodb-service.yaml
│   ├── mongodb-pvc.yaml
│   ├── api-deployment.yaml
│   ├── api-service.yaml
│   └── external-secret.yaml
├── overlays/
│   ├── dev/                       # Development environment
│   │   ├── kustomization.yaml
│   │   └── api-deployment-patch.yaml
│   └── prod/                      # Production environment
│       ├── kustomization.yaml
│       ├── api-deployment-patch.yaml
│       ├── mongodb-deployment-patch.yaml
│       └── ingress.yaml
├── argocd-application.yaml        # ArgoCD Application manifests
└── README.md
```

## Prerequisites

1. **External Secrets Operator** - For pulling secrets from GitHub
2. **ArgoCD** - For GitOps deployment
3. **Ingress Controller** (Traefik) - For production ingress
4. **Cert Manager** - For TLS certificates

### Install Prerequisites

```bash
# External Secrets Operator
kubectl apply -f https://raw.githubusercontent.com/external-secrets/external-secrets/main/deploy/charts/external-secrets/crds/bundled.yaml
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets -n external-secrets-system --create-namespace

# ArgoCD (if not already installed)
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
```

## Setup GitHub Secrets

1. In your GitHub repository, go to Settings > Secrets and Variables > Actions
2. Add the following repository secret:
   - `HARBORSEAL_JWT_SECRET`: Your JWT signing secret (generate with: `openssl rand -hex 32`)

3. Create a GitHub Personal Access Token with `repo` access
4. Update `external-secret.yaml` with your base64-encoded GitHub token:
   ```bash
   echo -n "your-github-token" | base64
   # Replace the token value in external-secret.yaml
   ```

## ArgoCD Deployment

### Apply ArgoCD Applications

```bash
kubectl apply -f kubernetes/argocd-application.yaml
```

This creates two ArgoCD applications:
- `harborseal-api-prod` - Production environment
- `harborseal-api-dev` - Development environment

### Force Sync with ArgoCD

```bash
# Sync production
argocd app sync harborseal-api-prod --force

# Sync development
argocd app sync harborseal-api-dev --force
```

### ArgoCD UI Access

```bash
# Get ArgoCD admin password
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

# Port forward to access UI
kubectl port-forward svc/argocd-server -n argocd 8080:443
# Visit https://localhost:8080
```

## Environment Configuration

### Development Environment
- **Namespace**: `harborseal-dev`
- **Replicas**: 1
- **Resources**: Lower limits for development
- **Database**: `harborseal-dev`

### Production Environment
- **Namespace**: `harborseal`
- **Replicas**: 3
- **Resources**: Higher limits for production
- **Database**: `harborseal`
- **Ingress**: Public HTTPS endpoint
- **TLS**: Let's Encrypt certificates

## Manual Deployment (Alternative)

If you prefer manual deployment without ArgoCD:

```bash
# Development
kubectl apply -k kubernetes/overlays/dev/

# Production
kubectl apply -k kubernetes/overlays/prod/
```

## Updating Configuration

1. Modify the appropriate overlay files
2. Commit and push to GitHub
3. ArgoCD will automatically detect changes and sync (if auto-sync enabled)
4. Or manually sync: `argocd app sync harborseal-api-prod --force`

## Security Notes

- JWT secrets are pulled from GitHub Actions secrets via External Secrets Operator
- MongoDB runs without authentication in this setup - add MongoDB authentication for production
- All containers run as non-root users
- Network policies can be added for additional isolation

## Monitoring

The API deployment includes Prometheus annotations for metrics scraping:
- Port: 8080
- Path: /metrics (if you add metrics endpoint)
- Health check: /health

## Troubleshooting

### Check Application Status
```bash
argocd app get harborseal-api-prod
```

### View Logs
```bash
kubectl logs -n harborseal -l app.kubernetes.io/component=api -f
```

### Check External Secrets
```bash
kubectl get externalsecret -n harborseal
kubectl describe externalsecret harborseal-secrets -n harborseal
```

### Force Resync
```bash
argocd app sync harborseal-api-prod --force --prune
```