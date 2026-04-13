---
title: "Kubernetes Security Best Practices"
date: 2025-08-10
description: "A guide to securing Kubernetes clusters covering RBAC, network policies, pod security standards, and runtime protection."
tags: ["kubernetes", "devops", "cloud", "blue-team", "hardening"]
categories: ["Security"]
image: "https://picsum.photos/seed/k8sec14/800/400"
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://github.com/0xrh0d4m1n.png"
---

## Kubernetes Attack Surface

Kubernetes introduces a **complex attack surface** that spans infrastructure, orchestration, and application layers. Misconfigurations are the leading cause of K8s security breaches.

### Common Misconfigurations

- Exposed API server without authentication
- Pods running as **root** with default service accounts
- Missing *network policies* allowing unrestricted pod-to-pod communication
- Secrets stored in plaintext ConfigMaps
- Overly permissive RBAC roles

## RBAC Configuration

### Principle of Least Privilege

```yaml
# Restricted Role: read-only access to pods in a namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: production
  name: pod-reader
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods-binding
  namespace: production
subjects:
  - kind: User
    name: analyst@company.com
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

### RBAC Audit Commands

```bash
# List all cluster role bindings
kubectl get clusterrolebindings -o wide

# Check what a specific user can do
kubectl auth can-i --list --as=analyst@company.com

# Find overly permissive roles
kubectl get clusterroles -o json | \
  jq '.items[] | select(.rules[].verbs[] == "*") | .metadata.name'
```

## Pod Security Standards

| Level | Description | Use Case |
|-------|-------------|----------|
| **Privileged** | Unrestricted | System-level workloads only |
| **Baseline** | Minimal restrictions | General workloads |
| **Restricted** | Hardened | Sensitive/production workloads |

### Restricted Pod Example

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    fsGroup: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: myapp:1.0@sha256:abc123...
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        limits:
          memory: "256Mi"
          cpu: "500m"
        requests:
          memory: "128Mi"
          cpu: "250m"
```

## Network Policies

By default, all pods can communicate with each other. **Network policies** act as firewall rules:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress: []
```

## Security Scanning Tools

- **kube-bench** -- CIS Kubernetes Benchmark checks
- **kubeaudit** -- audit cluster configurations
- **Falco** -- runtime threat detection
- **Trivy** -- container and K8s manifest scanning
- **Polaris** -- best practice validation

```bash
# Run kube-bench
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench

# Scan manifests with Trivy
trivy k8s --report summary cluster
```

> Treat your Kubernetes cluster as a **hostile environment** where every component must prove its trustworthiness through explicit policies and continuous monitoring.

Security in Kubernetes is a shared responsibility across platform teams and application developers. Implement these controls progressively and automate enforcement through admission controllers.
