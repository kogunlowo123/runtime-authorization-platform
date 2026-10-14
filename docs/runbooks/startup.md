# Runbook: first deployment and startup

## Prerequisites

- AKS (or EKS/GKE) ≥ 1.27 with workload identity enabled, the External
  Secrets Operator, and a `ClusterSecretStore` named `platform-secrets` bound
  to the cloud secret manager.
- Permission to create an Entra ID app registration in the tenant (Azure).
- `terraform` ≥ 1.7, `helm` ≥ 3.14, `az` (or `aws` / `gcloud`), `openssl`.

## 1. Provision cloud resources

```bash
cd deployments/terraform/azure        # or aws / gcp
terraform init                        # configure an encrypted remote backend first
terraform apply -var-file=<environment>.tfvars
```

Record the outputs: `entra_audience`, `entra_client_id`, `entra_tenant_id`,
`workload_identity_client_id`, `key_vault_uri`, `audit_container`.

## 2. Assign Entra app roles

Grant app roles on the platform's enterprise application:

| Role | Assign to |
|---|---|
| `Authz.Decide` | API/MCP gateways and tool servers (applications) |
| `Authz.Agent` | Agent applications (workload identities) |
| `Authz.PolicyAuthor`, `Authz.PolicyApprover` | Two different groups |
| `Authz.IntentApprover` | Business approvers |
| `Authz.SecurityOfficer`, `Authz.Auditor` | Security operations, internal audit |

## 3. Create the audit signing key (outside Terraform)

```bash
openssl genpkey -algorithm ed25519 -out audit-2026-10.pem
az keyvault secret set --vault-name <vault> \
  --name runtime-authorization-audit-key-2026-10 --file audit-2026-10.pem
shred -u audit-2026-10.pem
```

AWS: `aws secretsmanager create-secret --kms-key-id <kms_key_arn> ...`.
GCP: `gcloud secrets create ... --data-file=-`.

## 4. Namespace and secret sync

```bash
kubectl apply -k deployments/kubernetes
kubectl -n runtime-authorization get externalsecret   # READY=True for both
```

## 5. Install the chart

Create `<environment>.yaml` with every value marked REQUIRED in
`values.yaml` and the service-account annotation
`azure.workload.identity/client-id: <workload_identity_client_id>`:

```bash
helm upgrade --install authz oci://ghcr.io/kogunlowo123/charts/runtime-authorization-platform \
  --version 0.1.0 -n runtime-authorization -f <environment>.yaml --wait
```

On first start the platform bootstraps the reviewed policy from
`policies/runtime-authorization.yaml` after running its tests; afterwards the
database is the source of truth and changes go through
`docs/runbooks/policy-change.md`.

## 6. Verify

```bash
kubectl -n runtime-authorization rollout status statefulset/authz-runtime-authorization-platform
kubectl -n runtime-authorization port-forward svc/authz-runtime-authorization-platform 8080:80
curl -sf localhost:8080/readyz
curl -s localhost:8080/.well-known/agent-card.json | jq .url
TOKEN=$(az account get-access-token --resource <entra_audience> --query accessToken -o tsv)
curl -s -H "Authorization: Bearer $TOKEN" localhost:8080/v1/policies/active | jq .digest
```

Expected: `{"status":"ready",...}`, the public A2A URL, and the digest of the
bootstrapped policy (also on the Grafana "Active policy" panel).
