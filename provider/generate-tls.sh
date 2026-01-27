#!/bin/bash
# (c) 2026 JFrog Ltd.
set -o errexit -o pipefail

# =============================================================================
# TLS Certificate Generator for JFrog Evidence OPA Provider
# =============================================================================
# This script generates a self-signed CA and server certificates for the
# external data provider, then updates the provider.yaml with the CA bundle.
# =============================================================================

# Configuration
SERVICE_NAME="${SERVICE_NAME:-jfrog-evidence-opa-provider}"
SERVICE_NAMESPACE="${SERVICE_NAMESPACE:-gatekeeper-system}"
CERT_VALIDITY_DAYS="${CERT_VALIDITY_DAYS:-365}"
OUTPUT_DIR="${OUTPUT_DIR:-./certs}"
PROVIDER_YAML="${PROVIDER_YAML:-./provider.yaml}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create output directory
mkdir -p "${OUTPUT_DIR}"
cd "${OUTPUT_DIR}"

log_info "Generating TLS certificates for ${SERVICE_NAME}.${SERVICE_NAMESPACE}"
log_info "Output directory: ${OUTPUT_DIR}"
log_info "Certificate validity: ${CERT_VALIDITY_DAYS} days"

# =============================================================================
# Step 1: Generate CA private key
# =============================================================================
log_info "Step 1/5: Generating CA private key..."
openssl genrsa -out ca.key 2048 2>&1 | cat

# =============================================================================
# Step 2: Generate self-signed CA certificate
# =============================================================================
log_info "Step 2/5: Generating self-signed CA certificate..."
openssl req -new -x509 \
    -days "${CERT_VALIDITY_DAYS}" \
    -key ca.key \
    -subj "/O=JFrog/CN=JFrog Evidence OPA Provider CA" \
    -out ca.crt 2>&1 | cat

# =============================================================================
# Step 3: Generate server private key
# =============================================================================
log_info "Step 3/5: Generating server private key..."
openssl genrsa -out server.key 2048 2>&1 | cat

# =============================================================================
# Step 4: Generate server CSR
# =============================================================================
log_info "Step 4/5: Generating server certificate signing request (CSR)..."
openssl req -newkey rsa:2048 -nodes \
    -keyout server.key \
    -subj "/CN=${SERVICE_NAME}.${SERVICE_NAMESPACE}" \
    -out server.csr 2>&1 | cat

# =============================================================================
# Step 5: Generate server certificate signed by CA
# =============================================================================
log_info "Step 5/5: Generating server certificate signed by CA..."
openssl x509 -req \
    -extfile <(printf "subjectAltName=DNS:${SERVICE_NAME}.${SERVICE_NAMESPACE},DNS:${SERVICE_NAME}.${SERVICE_NAMESPACE}.svc,DNS:${SERVICE_NAME}.${SERVICE_NAMESPACE}.svc.cluster.local") \
    -days "${CERT_VALIDITY_DAYS}" \
    -in server.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out server.crt 2>&1 | cat

# =============================================================================
# Generate Base64-encoded CA bundle
# =============================================================================
log_info "Generating base64-encoded CA bundle..."
CA_BUNDLE=$(cat ca.crt | base64 | tr -d '\n')

# Save CA bundle to a file for reference
echo "${CA_BUNDLE}" > ca.bundle.b64
log_info "CA bundle saved to: ${OUTPUT_DIR}/ca.bundle.b64"

# =============================================================================
# Update provider.yaml with CA bundle
# =============================================================================
PROVIDER_YAML_PATH="../provider.yaml"
if [[ -f "${PROVIDER_YAML_PATH}" ]]; then
    log_info "Updating ${PROVIDER_YAML_PATH} with CA bundle..."
    
    # Use sed to replace the caBundle value
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS sed requires empty string for -i
        sed -i '' "s|caBundle:.*|caBundle: ${CA_BUNDLE}|g" "${PROVIDER_YAML_PATH}"
    else
        # Linux sed
        sed -i "s|caBundle:.*|caBundle: ${CA_BUNDLE}|g" "${PROVIDER_YAML_PATH}"
    fi
    
    log_info "provider.yaml updated successfully!"
else
    log_warn "provider.yaml not found at ${PROVIDER_YAML_PATH}"
    log_warn "Please manually update the caBundle field with the value in ca.bundle.b64"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "============================================================================="
log_info "TLS certificates generated successfully!"
echo "============================================================================="
echo ""
echo "Generated files in ${OUTPUT_DIR}:"
echo "  - ca.key          : CA private key"
echo "  - ca.crt          : CA certificate"
echo "  - server.key      : Server private key"
echo "  - server.csr      : Server certificate signing request"
echo "  - server.crt      : Server certificate (signed by CA)"
echo "  - ca.bundle.b64   : Base64-encoded CA certificate for provider.yaml"
echo ""

# =============================================================================
# Create Kubernetes TLS Secret
# =============================================================================
echo ""
read -p "Do you want to create the Kubernetes TLS secret now? (y/n): " CREATE_TLS_SECRET

if [[ "${CREATE_TLS_SECRET}" =~ ^[Yy]$ ]]; then
    log_info "Creating Kubernetes TLS secret 'jfrog-provider-tls'..."
    
    # Check if secret already exists
    if kubectl get secret jfrog-provider-tls -n "${SERVICE_NAMESPACE}" &>/dev/null; then
        log_warn "Secret 'jfrog-provider-tls' already exists in namespace '${SERVICE_NAMESPACE}'"
        read -p "Do you want to delete and recreate it? (y/n): " RECREATE_SECRET
        if [[ "${RECREATE_SECRET}" =~ ^[Yy]$ ]]; then
            kubectl delete secret jfrog-provider-tls -n "${SERVICE_NAMESPACE}" 2>&1 | cat
        else
            log_info "Skipping TLS secret creation."
        fi
    fi
    
    # Create the secret if it doesn't exist (or was just deleted)
    if ! kubectl get secret jfrog-provider-tls -n "${SERVICE_NAMESPACE}" &>/dev/null; then
        kubectl create secret tls jfrog-provider-tls \
            --cert=./server.crt \
            --key=./server.key \
            -n "${SERVICE_NAMESPACE}" 2>&1 | cat
        log_info "TLS secret 'jfrog-provider-tls' created successfully!"
    fi
else
    log_info "Skipping TLS secret creation."
    echo ""
    echo "To create the TLS secret manually, run:"
    echo ""
    echo "   kubectl create secret tls jfrog-provider-tls \\"
    echo "     --cert=${OUTPUT_DIR}/server.crt \\"
    echo "     --key=${OUTPUT_DIR}/server.key \\"
    echo "     -n ${SERVICE_NAMESPACE}"
    echo ""
fi

# =============================================================================
# Create JFrog Token Secret (Interactive)
# =============================================================================
echo ""
echo "============================================================================="
log_info "JFrog Token Secret Setup"
echo "============================================================================="
echo ""
echo -e "${YELLOW}Important Notes:${NC}"
echo "  - Gatekeeper uses mutual TLS; ensure the provider trusts Gatekeeper's CA."
echo "  - The deployment mounts 'gatekeeper-webhook-server-cert' as /tmp/gatekeeper/ca.crt"
echo "  - JFrog access token (key must be 'token', the pod reads JFROG_TOKEN_SECRET)"
echo ""

read -p "Do you want to create the JFrog token secret now? (y/n): " CREATE_TOKEN_SECRET

if [[ "${CREATE_TOKEN_SECRET}" =~ ^[Yy]$ ]]; then
    echo ""
    read -p "Enter your JFrog access token: " JFROG_TOKEN
    
    if [[ -z "${JFROG_TOKEN}" ]]; then
        log_error "Token cannot be empty. Skipping JFrog token secret creation."
    else
        log_info "Creating Kubernetes secret 'jfrog-token-secret'..."
        
        # Check if secret already exists
        if kubectl get secret jfrog-token-secret -n "${SERVICE_NAMESPACE}" &>/dev/null; then
            log_warn "Secret 'jfrog-token-secret' already exists in namespace '${SERVICE_NAMESPACE}'"
            read -p "Do you want to delete and recreate it? (y/n): " RECREATE_TOKEN
            if [[ "${RECREATE_TOKEN}" =~ ^[Yy]$ ]]; then
                kubectl delete secret jfrog-token-secret -n "${SERVICE_NAMESPACE}" 2>&1 | cat
            else
                log_info "Skipping JFrog token secret creation."
                JFROG_TOKEN=""
            fi
        fi
        
        # Create the secret if token is set (wasn't skipped)
        if [[ -n "${JFROG_TOKEN}" ]] && ! kubectl get secret jfrog-token-secret -n "${SERVICE_NAMESPACE}" &>/dev/null; then
            kubectl -n "${SERVICE_NAMESPACE}" create secret generic jfrog-token-secret \
                --from-literal=token="${JFROG_TOKEN}" 2>&1 | cat
            log_info "JFrog token secret 'jfrog-token-secret' created successfully!"
        fi
    fi
else
    log_info "Skipping JFrog token secret creation."
    echo ""
    echo "To create the JFrog token secret manually, run:"
    echo ""
    echo "   kubectl -n ${SERVICE_NAMESPACE} create secret generic jfrog-token-secret \\"
    echo "     --from-literal=token=<your_jfrog_token>"
    echo ""
fi

# =============================================================================
# Final Steps
# =============================================================================
echo ""
echo "============================================================================="
log_info "Next Steps"
echo "============================================================================="
echo ""
echo "1. Apply the updated provider.yaml:"
echo ""
echo "   kubectl apply -f ./provider.yaml -n gatekeeper-system"
echo ""
echo "2. Deploy the JFrog Evidence OPA Provider:"
echo ""
echo "   kubectl apply -f ./deployment.yaml -n gatekeeper-system"
echo ""
echo "============================================================================="
