# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to `contact@agentsbloom.com` with the subject `AgentsBloom SDK security report`. Include the affected package version, a concise reproduction, and the impact. Do not include live API keys, payment credentials, signing secrets, personal data, or private repository URLs in the report.

We will acknowledge a report when practical, investigate it privately, and coordinate a fix and disclosure timeline with the reporter. Please do not disclose an unpatched vulnerability in a public issue or pull request.

## Supported versions

The latest published version is the primary supported version. Security fixes may not be backported to end-of-life versions.

## Deployment guidance

- Configure a unique high-entropy `AGENTSBLOOM_SECRET` for every merchant deployment.
- Keep secrets in the deployment secret manager or environment, never in source control or browser bundles.
- Do not use `demoMode` or `disableSignatureAuth` for internet-facing production traffic.
- Use HTTPS, durable authorization, and a distributed rate/idempotency store for production systems.
- Rotate any credential that has appeared in logs, chat, tickets, shell history, or a repository.
