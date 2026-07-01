# Secrets Management with Sealed Secrets

## One-time cluster setup
kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/latest/download/controller.yaml

## Install kubeseal CLI
# macOS: brew install kubeseal
# Linux: https://github.com/bitnami-labs/sealed-secrets/releases

## Seal your secrets (run once per cluster)
# 1. Fill in deploy/k8s/secrets.yaml.template with real base64-encoded values
# 2. Seal it:
kubeseal --format yaml < deploy/k8s/secrets.yaml.template > deploy/k8s/sealed-secrets/byzantium-sealed.yaml
# 3. Commit deploy/k8s/sealed-secrets/byzantium-sealed.yaml to git (safe — encrypted)
# 4. Deploy: kubectl apply -f deploy/k8s/sealed-secrets/byzantium-sealed.yaml

## Rotating a secret
# 1. Update the plaintext value in secrets.yaml.template (DO NOT commit this file)
# 2. Re-seal and commit byzantium-sealed.yaml
# 3. kubectl rollout restart deployment/byzantium-gateway
