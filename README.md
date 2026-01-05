# JFrog Evidence Verify OPA Gatekeeper Provider

This project offers an External Data Provider for OPA Gatekeeper that checks JFrog Evidence records for container images before they are admitted to the cluster.

## 🎯 What this repo contains
- `provider/`: Go service implementing the External Data Provider plus Kubernetes deployment, service, and OPA Gatekeeper Provider resources.
- `templates/`: Gatekeeper `ConstraintTemplate` that calls the provider and acts according it its response.
- `policies/`: Example constraints configuring which registries and repositories are checked, and which predicate types must be present for images evidence.

## 📋 Prerequisites
- Kubernetes cluster with Gatekeeper v3.11+ and External Data enabled (mutual TLS required).
- JFrog Platform with Evidence feature and an access token that can query image metadata and evidence.
- TLS materials for the provider pod (`server.crt`/`server.key`) and Gatekeeper’s CA (`ca.crt`).

## Build and publish the provider image
1) Build the providfer image from `provider/`:
```
cd provider
docker buildx build --platform linux/<your platform> -t provider:<version> .
```
make sure to set platform (for example arm64) and image tag 

## Prepare Kubernetes secrets (namespaces: `gatekeeper-system`)
The secrets required for the provider to work are:
- Provider TLS secrets used by the provider Pod
- JFrog token allowing the provider to call JFrog platform APIs, token required should have permissions to read and annotate the docker repositories whoes workloadds are being validated 

To Setup TLS and Access for the provider follow the below instructions:
- TLS for the provider pod (paths are examples; adjust to your cert files):
follow the instructions on  
https://open-policy-agent.github.io/gatekeeper/website/docs/v3.11.x/externaldata/#tls-and-mutual-tls-support to create TLS resources required for the OPA gatekeeper server communication with the provider.
Once done, use the below instructions to prepare the TLS resources for the provider usage:
```
kubectl create secret tls jfrog-provider-tls \
  --cert=./server.crt --key=./server.key \
  -n gatekeeper-system
```
- Gatekeeper uses mutual TLS; ensure the provider trusts Gatekeeper’s CA. The deployment mounts `gatekeeper-webhook-server-cert` as `/tmp/gatekeeper/ca.crt`.
- JFrog access token (key must be `token`, the pod reads `JFROG_TOKEN_SECRET`):

*Notice that on AWS EKS you can use https://github.com/jfrog/jfrog-registry-operator for creating JFrog image pull secrets and also generic secrets that are short lived nad auto-rotated. 
```
kubectl -n gatekeeper-system create secret generic jfrog-token-secret --from-literal=token=<jfrog_token>
```

## 🚀 Deploy the JFrog provider
Apply the manifests (edit images/tags as needed):
```
kubectl -n gatekeeper-system apply -f provider/deployment.yaml
kubectl -n gatekeeper-system apply -f provider/provider.yaml
```
The deployment expects:
- secret `gatekeeper-webhook-server-cert` with OPA Gatekeeper server CA.
- TLS cert/key from `jfrog-provider-tls` secret created in the previous step.

## 🔧 Install the Gatekeeper policy
1) Install the `ConstraintTemplate`:
```
kubectl apply -f templates/jfrogcheckevidence.yaml
```
2) Create a constraint with your settings (registries, repositories, predicate types). Examples are provided:
```
kubectl apply -f policies/jfrog_check_evidence.yaml
```
Key parameters:
- `checkedRegistries`: registries to evaluate (images from other registeries are not checked).
- `checkedRepositories`: optional repository allowlist, leave empty to have all repositories checked.
- `checkedPredicateTypes`: evidence predicate types that must be present _and verified_ for each image.

## 🔍 How the provider validates images (high level)
- Gatekeeper sends keys where the first entry is a comma-separated list of predicate types and the rest are image references.
- For each image, the provider:
  - Sends a `HEAD` api call to JFrog Artifactory to obtain the digest and manifest filename of the image.
  - Queries JFrog Evidence GraphQL (`/onemodel/api/v1/graphql`) for the evidence collection attached to the image.
  - Returns `_valid` or `_invalid` per image back to Gatekeeper; any missing evidence predicate type yields a violation.
- Set `DEBUG=true` to log requests/responses inside the provider pod.

## Try it out
With the constraint installed, apply a Pod to check the policy:
```
kubectl apply -f pod.yaml
```
If the required evidence is missing or unverified, the admission request will be rejected with a message that includes the checked images and provider response.
Notice this ConstraintTemplate is targeting Pods, if the need is to validate deployments, then the ConstraintTemplate needs to chaknge and collect images from 
input.review.object.spec.template.spec.containers[_].image
and from 
input.review.object.spec.template.spec.initContainers[_].image

In case the pod is within the validation scope and the validation is successful, the pod will be created (validation logs can be viewed inside the provider pod log). 

In case the evidence validation is not successful, a message will appear and the pod deployment will fail. see below an example for such a failure:

``
Error from server (Forbidden): error when creating "my-pod.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [jfrog-check-evidence] TARGET IMAGES: ["myjfrog.jfrog.io/docker-local/my-image:1.0.0"], RESPONSE: {"errors": [], "responses": [["myjfrog.jfrog.io/docker-local/my-image:1.0.0", "_invalid"]], "status_code": 200, "system_error": ""}
``

In case the validtion fails on an error communicating with the server, or some other failure, a different message is returned:
``
Error from server (Forbidden): error when creating "my-image.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [jfrog-check-evidence] TARGET IMAGES: ["myjfrog.jfrog.io/docker-local/my-image:1.0"], RESPONSE: {"errors": [], "responses": [], "status_code": 200, "system_error": "unable to get digest for myjfrog.jfrog.io/docker-local/my-image:1.0: failed to get digest, response status: 401 Unauthorized"}
``

More information can be viewed on the provider log.


## Notes

- The provider listens on `:8443` with TLS 1.3 and requires client certs from Gatekeeper.
- Update the container image reference in `provider/deployment.yaml` before production use.
- In order to simplify the setup process, especiall the TLS setup, these instructions are installing the provider under the gatekeeper-system namespace

## 📚 Additional Resources
- [OPA Gatekeeper Documentation](https://open-policy-agent.github.io/gatekeeper/website/)
- [GraphQL Documentation](https://graphql.org/learn/)
- [JFrog Platform Documentation](https://www.jfrog.com/confluence/)

## 🤝 Contributing

Feel free to submit issues and enhancement requests!
