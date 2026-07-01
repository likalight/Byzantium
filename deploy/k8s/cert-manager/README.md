# cert-manager Setup

## Prerequisites
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.yaml

## Deploy
1. Set your domain: `export BYZANTIUM_DOMAIN=api.yourdomain.com`
2. Set your email: `export CERT_MANAGER_EMAIL=admin@yourdomain.com`
3. Apply with substitution:
   envsubst < deploy/k8s/cert-manager/issuer.yaml | kubectl apply -f -
   envsubst < deploy/k8s/cert-manager/certificate.yaml | kubectl apply -f -
   envsubst < deploy/k8s/ingress.yaml | kubectl apply -f -
4. Check status: `kubectl describe certificate byzantium-gateway-tls`
