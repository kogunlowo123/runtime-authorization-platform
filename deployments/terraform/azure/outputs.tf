output "workload_identity_client_id" {
  description = "Annotate the service account with azure.workload.identity/client-id = this value"
  value       = azurerm_user_assigned_identity.authz.client_id
}

output "key_vault_uri" {
  description = "Key Vault holding the database URL and audit-key secrets"
  value       = azurerm_key_vault.authz.vault_uri
}

output "audit_container" {
  description = "Immutable blob container receiving audit chains"
  value       = "${azurerm_storage_account.audit.name}/${azurerm_storage_container.audit.name}"
}

output "entra_audience" {
  description = "Set authz.entra.audiences to this value (and the client id)"
  value       = azuread_application_identifier_uri.authz.identifier_uri
}

output "entra_client_id" {
  description = "Client id of the platform's Entra app registration"
  value       = azuread_application.authz.client_id
}

output "entra_tenant_id" {
  description = "Set authz.entra.tenantIds to this value"
  value       = var.tenant_id
}
