# Webhook Integration Guide

This guide explains how to integrate InfraPilot with CI/CD systems using webhooks for automated deployments.

## Table of Contents

- [Overview](#overview)
- [Creating a Webhook](#creating-a-webhook)
- [GitHub Actions](#github-actions)
- [GitLab CI](#gitlab-ci)
- [Generic/Jenkins](#genericjenkins)
- [Payload Format](#payload-format)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

## Overview

InfraPilot webhooks enable automated deployments directly from your CI/CD pipeline. When your CI/CD system completes a build, it sends a webhook to InfraPilot which then:

1. Receives and verifies the webhook payload
2. Extracts build metadata (commit, branch, image info)
3. Creates a deployment
4. Triggers the security pipeline (scan → SBOM → policy evaluation)
5. Deploys the container if policies allow

**Flow**: CI Build → Webhook → InfraPilot → Security Scan → Policy Check → Deploy

## Creating a Webhook

### Via UI

1. Navigate to **Webhooks** in the InfraPilot dashboard
2. Click **Create Webhook**
3. Configure:
   - **Name**: Descriptive name (e.g., "MyApp Production")
   - **Provider**: GitHub Actions, GitLab CI, Jenkins, or Generic
   - **Service Name**: The service this webhook deploys
   - **Environment**: dev, staging, or prod
4. Click **Create**
5. **Copy the webhook URL and secret** (secret is only shown once!)

### Via API

```bash
curl -X POST https://infrapilot.example.com/api/v1/agents/{agent_id}/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MyApp Production",
    "provider": "github",
    "service_name": "myapp",
    "environment": "prod"
  }'
```

Response includes the `webhook_url` and `secret` (one-time only).

## GitHub Actions

### Workflow Example

Create `.github/workflows/deploy.yml`:

```yaml
name: Build and Deploy to InfraPilot

on:
  push:
    branches: [main]

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2

      - name: Log in to Container Registry
        uses: docker/login-action@v2
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push Docker image
        uses: docker/build-push-action@v4
        with:
          context: .
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}

      - name: Trigger InfraPilot Deployment
        run: |
          curl -X POST ${{ secrets.INFRAPILOT_WEBHOOK_URL }} \
            -H "Content-Type: application/json" \
            -d '{
              "repository": {
                "full_name": "${{ github.repository }}",
                "clone_url": "${{ github.repositoryUrl }}",
                "html_url": "${{ github.server_url }}/${{ github.repository }}"
              },
              "head_commit": {
                "id": "${{ github.sha }}",
                "message": "${{ github.event.head_commit.message }}",
                "author": {
                  "name": "${{ github.event.head_commit.author.name }}"
                }
              },
              "ref": "${{ github.ref }}",
              "workflow_run": {
                "id": ${{ github.run_id }},
                "run_number": ${{ github.run_number }},
                "html_url": "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}",
                "head_branch": "${{ github.ref_name }}",
                "head_sha": "${{ github.sha }}"
              },
              "deployment": {
                "image_repository": "ghcr.io/${{ github.repository }}",
                "image_tag": "${{ github.sha }}",
                "image_digest": null
              }
            }'
```

### Required Secrets

Add to your GitHub repository secrets:
- `INFRAPILOT_WEBHOOK_URL`: The webhook URL from InfraPilot

### Signature Verification (Optional)

For enhanced security, GitHub can sign webhooks:

```yaml
- name: Trigger InfraPilot Deployment
  run: |
    PAYLOAD='{"deployment": {...}}'
    SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "${{ secrets.INFRAPILOT_WEBHOOK_SECRET }}" | sed 's/^.* //')
    curl -X POST ${{ secrets.INFRAPILOT_WEBHOOK_URL }} \
      -H "Content-Type: application/json" \
      -H "X-Hub-Signature-256: sha256=$SIGNATURE" \
      -d "$PAYLOAD"
```

## GitLab CI

### Pipeline Example

Create `.gitlab-ci.yml`:

```yaml
stages:
  - build
  - deploy

variables:
  IMAGE_TAG: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA

build:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  before_script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
  script:
    - docker build -t $IMAGE_TAG .
    - docker push $IMAGE_TAG

deploy:
  stage: deploy
  image: curlimages/curl:latest
  script:
    - |
      curl -X POST $INFRAPILOT_WEBHOOK_URL \
        -H "Content-Type: application/json" \
        -H "X-Gitlab-Token: $INFRAPILOT_WEBHOOK_SECRET" \
        -d "{
          \"object_kind\": \"deployment\",
          \"project\": {
            \"name\": \"$CI_PROJECT_NAME\",
            \"git_http_url\": \"$CI_REPOSITORY_URL\",
            \"web_url\": \"$CI_PROJECT_URL\",
            \"path_with_namespace\": \"$CI_PROJECT_PATH\"
          },
          \"commit\": {
            \"id\": \"$CI_COMMIT_SHA\",
            \"message\": \"$CI_COMMIT_MESSAGE\",
            \"author\": {
              \"name\": \"$GITLAB_USER_NAME\"
            }
          },
          \"ref\": \"$CI_COMMIT_REF_NAME\",
          \"pipeline\": {
            \"id\": $CI_PIPELINE_ID,
            \"web_url\": \"$CI_PIPELINE_URL\"
          },
          \"deployment\": {
            \"image_repository\": \"$CI_REGISTRY_IMAGE\",
            \"image_tag\": \"$CI_COMMIT_SHORT_SHA\",
            \"image_digest\": null
          }
        }"
  only:
    - main
```

### Required Variables

Add to GitLab CI/CD variables:
- `INFRAPILOT_WEBHOOK_URL`: The webhook URL
- `INFRAPILOT_WEBHOOK_SECRET`: The webhook secret

## Generic/Jenkins

For Jenkins or other CI systems, use the generic webhook format:

### Jenkins Pipeline Example

```groovy
pipeline {
    agent any

    environment {
        IMAGE_REPO = 'myregistry.com/myapp'
        IMAGE_TAG = "${GIT_COMMIT.take(8)}"
    }

    stages {
        stage('Build') {
            steps {
                sh "docker build -t ${IMAGE_REPO}:${IMAGE_TAG} ."
                sh "docker push ${IMAGE_REPO}:${IMAGE_TAG}"
            }
        }

        stage('Deploy') {
            steps {
                script {
                    def payload = """
                    {
                        "git_repo": "${GIT_URL}",
                        "git_branch": "${GIT_BRANCH}",
                        "git_commit": "${GIT_COMMIT}",
                        "commit_message": "${env.GIT_COMMIT_MSG}",
                        "author": "${env.GIT_AUTHOR_NAME}",
                        "ci_provider": "jenkins",
                        "ci_pipeline_id": "${BUILD_NUMBER}",
                        "ci_build_url": "${BUILD_URL}",
                        "image_repository": "${IMAGE_REPO}",
                        "image_tag": "${IMAGE_TAG}"
                    }
                    """

                    sh """
                        curl -X POST ${INFRAPILOT_WEBHOOK_URL} \
                          -H "Content-Type: application/json" \
                          -H "X-Webhook-Signature: \$(echo -n '${payload}' | openssl dgst -sha256 -hmac '${INFRAPILOT_WEBHOOK_SECRET}' | sed 's/^.* //')" \
                          -d '${payload}'
                    """
                }
            }
        }
    }
}
```

## Payload Format

### Generic Webhook Payload

All providers should send a JSON payload with the following structure:

```json
{
  "git_repo": "https://github.com/user/repo.git",
  "git_branch": "main",
  "git_commit": "abc123def456",
  "commit_message": "Fix: Resolve authentication bug",
  "author": "Jane Doe",
  "ci_provider": "github",
  "ci_pipeline_id": "12345",
  "ci_build_url": "https://github.com/user/repo/actions/runs/12345",
  "build_number": "42",
  "image_repository": "ghcr.io/user/repo",
  "image_tag": "abc123",
  "image_digest": "sha256:abc123..." // Optional
}
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `git_repo` | string | Git repository clone URL |
| `git_branch` | string | Branch name (e.g., "main") |
| `git_commit` | string | Full commit SHA |
| `image_repository` | string | Docker image repository |
| `image_tag` | string | Docker image tag |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `image_digest` | string | SHA256 digest of the image |
| `commit_message` | string | Commit message |
| `author` | string | Commit author name |
| `ci_provider` | string | CI provider name |
| `ci_pipeline_id` | string | CI pipeline/build ID |
| `ci_build_url` | string | Link to CI build |
| `build_number` | string | Build number |

## Security

### Webhook Signatures

**Note**: Current implementation stores secrets as bcrypt hashes for authentication purposes. Signature verification is planned for a future update.

For now, webhooks are authenticated via the webhook URL itself (which includes a UUID). Keep webhook URLs secret and rotate them if compromised.

### Best Practices

1. **Use HTTPS**: Always use HTTPS for webhook URLs in production
2. **Rotate Secrets**: Periodically regenerate webhook secrets
3. **Limit Scope**: Create separate webhooks for each service/environment
4. **Monitor Events**: Check the webhook events log for failed attempts
5. **IP Allowlisting**: Consider firewall rules to only allow your CI/CD IPs

### Disabling Compromised Webhooks

If a webhook is compromised:

1. Disable it immediately in the InfraPilot UI
2. Create a new webhook with a new secret
3. Update your CI/CD configuration
4. Delete the old webhook

## Troubleshooting

### Webhook Not Triggering

**Check**:
1. Webhook is enabled in InfraPilot
2. CI/CD job is reaching the webhook step (check CI logs)
3. Network connectivity (firewall, DNS)
4. Webhook URL is correct (copy again from InfraPilot)

### Deployment Fails After Webhook

**Check webhook events** in InfraPilot:
1. Navigate to Webhooks → Select your webhook → Recent Events
2. Look for error messages
3. Common issues:
   - Missing required fields in payload
   - Image not accessible (registry authentication)
   - Policy denied deployment (check scan results)

### Image Not Found

Ensure:
1. Image was pushed to registry before webhook
2. Image tag matches exactly
3. InfraPilot can authenticate to your registry
4. Image repository URL is correct (include registry hostname)

### Policy Denied Deployment

If deployment is blocked by policy:
1. Check deployment details for scan results
2. Review vulnerabilities found
3. Check policy rules for your environment
4. Fix vulnerabilities or adjust policy as needed

### Debugging Webhook Payloads

Use a request inspector to see what your CI is sending:

```bash
# Temporary test webhook (use RequestBin or similar)
curl -X POST https://requestbin.com/your-id \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'
```

Compare with InfraPilot's expected format.

## Examples

### Complete GitHub Actions Example

See [examples/github-actions-webhook.yml](../examples/github-actions-webhook.yml)

### Complete GitLab CI Example

See [examples/gitlab-ci-webhook.yml](../examples/gitlab-ci-webhook.yml)

### Complete Jenkins Example

See [examples/Jenkinsfile.webhook](../examples/Jenkinsfile.webhook)

---

**Need Help?** Check the [FAQ](./FAQ.md) or open an issue on [GitHub](https://github.com/infrapilot/infrapilot-community/issues).
