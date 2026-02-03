---
name: containers
description: Skills for attacking container and orchestration platforms including Docker and Kubernetes.
compatibility: Requires docker, kubectl
allowed-tools: docker kubectl crictl
metadata:
  category: network
---

# Container Services

Container and orchestration platform exploitation.

## Skills

- [Docker Pentesting](references/docker-pentesting.md) - Docker API (2375/2376)
- [Docker Registry](references/docker-registry-pentesting.md) - Registry API (5000)
- [Kubernetes Pentesting](references/kubernetes-pentesting.md) - K8s API (6443/10250)

## Quick Reference

| Service | Port | Key Attack |
|---------|------|------------|
| Docker API | 2375 | Unauthenticated RCE |
| Registry | 5000 | Image extraction |
| K8s API | 6443 | Anonymous access |
| Kubelet | 10250 | Pod exec |
