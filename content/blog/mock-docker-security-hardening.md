---
title: "Docker Security Hardening: Best Practices"
date: 2024-09-30
description: "Comprehensive guide to securing Docker containers, images, and the Docker daemon in production environments."
tags: ["docker", "devops", "linux", "blue-team", "hardening"]
categories: ["Security"]
image: "https://picsum.photos/seed/docker9/800/400"
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://github.com/0xrh0d4m1n.png"
---

## Why Docker Security Matters

Containers share the host kernel, which means a **container escape** can compromise the entire host system. Securing Docker is not optional -- it is *critical* for production deployments.

## Image Security

### Use Minimal Base Images

```dockerfile
# BAD: Full Ubuntu image (77MB+ attack surface)
FROM ubuntu:22.04

# GOOD: Minimal Alpine image (~5MB)
FROM alpine:3.19

# BEST: Distroless for production
FROM gcr.io/distroless/static-debian12
```

### Scan Images for Vulnerabilities

```bash
# Using Trivy
trivy image myapp:latest

# Using Docker Scout
docker scout cves myapp:latest

# Using Grype
grype myapp:latest
```

## Runtime Security

### Drop Unnecessary Capabilities

```yaml
# docker-compose.yml
services:
  webapp:
    image: myapp:latest
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
```

### Security Checklist

| Control | Command/Config | Risk if Missing |
|---------|---------------|----------------|
| Run as non-root | `USER 1001` in Dockerfile | Container escape |
| Read-only filesystem | `--read-only` flag | Malware persistence |
| Drop capabilities | `--cap-drop ALL` | Privilege escalation |
| Resource limits | `--memory` / `--cpus` | DoS attacks |
| No privileged mode | Avoid `--privileged` | Full host access |
| Network isolation | Custom bridge networks | Lateral movement |

### Secure Dockerfile Example

```dockerfile
FROM alpine:3.19 AS builder
RUN apk add --no-cache go
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -o server .

FROM gcr.io/distroless/static-debian12
COPY --from=builder /app/server /server
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/server"]
```

## Daemon Configuration

Harden the Docker daemon by editing `/etc/docker/daemon.json`:

```json
{
  "icc": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "no-new-privileges": true,
  "userns-remap": "default",
  "live-restore": true,
  "storage-driver": "overlay2"
}
```

## Secrets Management

Never embed secrets in images:

- Use **Docker Secrets** (Swarm mode) or external vaults
- Mount secrets as *read-only volumes* at runtime
- Leverage `--secret` flag in BuildKit for build-time secrets
- Scan for leaked secrets using tools like `trufflehog` or `gitleaks`

```bash
# Using BuildKit secrets during build
DOCKER_BUILDKIT=1 docker build \
  --secret id=api_key,src=./api_key.txt \
  -t myapp:latest .
```

> Treat every container as potentially compromised. Defense in depth means securing images, runtime, networking, and the daemon itself.

Regularly audit your Docker environment with tools like **Docker Bench for Security** and integrate scanning into your CI/CD pipeline.
