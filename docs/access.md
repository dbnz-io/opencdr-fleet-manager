# Access setup

Use AWS roles or IAM Identity Center profiles. No IAM user is required. These
permissions are distinct:

1. **Deployment operator:** creates/updates this Serverless stack in the security
   account, including its Lambda roles, API Gateway, DynamoDB, queues, logs and
   schedule. Your existing infrastructure deployment role may need its resource
   naming restrictions expanded to include `opencdr-fleet-manager-*`.
2. **Credential onboarding operator:** manages API Gateway scoped keys/usage-plan
   bindings in each agent account and writes SecureStrings under this fleet's SSM
   prefix in the security account. These permissions stay on the operator's local
   profiles; normal Fleet polling does not assume member-account roles.
3. **API caller:** invokes specified fleet API paths using temporary AWS credentials.
   It needs no DynamoDB access, no SSM GetParameter and no deployment permissions.

Replace `REGION`, `SECURITY_ACCOUNT`, `API_ID` and `STAGE` in the policies below
with deployment outputs. Attach the resulting policy to your workload or operator
role using your organization's existing IAM process.

## Read-only fleet caller

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "execute-api:Invoke",
    "Resource": [
      "arn:aws:execute-api:REGION:SECURITY_ACCOUNT:API_ID/STAGE/GET/v1/*",
      "arn:aws:execute-api:REGION:SECURITY_ACCOUNT:API_ID/STAGE/POST/v1/fleet/read"
    ]
  }]
}
```

This grants the organization's full fleet read surface, including cached lists
and notification metadata. For access to one agent only, grant that agent's
specific paths instead of global inventory, statuses or bulk endpoints.

## Agent operator

Add explicitly authorized mutation paths to the read policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "execute-api:Invoke",
    "Resource": [
      "arn:aws:execute-api:REGION:SECURITY_ACCOUNT:API_ID/STAGE/POST/v1/agents/*/api/*",
      "arn:aws:execute-api:REGION:SECURITY_ACCOUNT:API_ID/STAGE/PUT/v1/agents/*/api/*",
      "arn:aws:execute-api:REGION:SECURITY_ACCOUNT:API_ID/STAGE/DELETE/v1/agents/*/api/*",
      "arn:aws:execute-api:REGION:SECURITY_ACCOUNT:API_ID/STAGE/POST/v1/fleet/invoke",
      "arn:aws:execute-api:REGION:SECURITY_ACCOUNT:API_ID/STAGE/POST/v1/agents/*/refresh"
    ]
  }]
}
```

Core scopes and the registration's `allow_writes` still apply. This includes
potentially destructive rule/list deletes and response rollback; narrow paths
further for your operators. It does not grant registration changes.

## Fleet registry administrator

An administrator additionally needs POST `/v1/agents` and PUT
`/v1/agents/*`, and permission for the credential provisioning process if they
manage credentials. IAM paths do not inspect JSON bodies; do not grant bulk
invoke to a caller expected to control only one member account.

For a hosted Web/MCP application, use its supported workload identity to obtain
short-lived credentials for an invoke-only role. Signing an operational request
does not authorize infrastructure deployment. Do not copy local AWS profiles or
permanent AWS access keys into the browser. Cross-account caller access also
requires the security account's API resource policy to allow the intended caller,
configured through your existing AWS access process. Client connectors are a
separate integration step; this service does not configure Vercel/OIDC for you.
