# get_kubectl_describe: closed list of resource types, no secrets or configmaps

Date: 2026-11-10
Status: accepted

## Decision

`get_kubectl_describe` excludes `secret` and `configmap`. The resource type is a
closed list of 18 types (pod, node, deployment, service, ingress, pvc and so on);
anything outside it is rejected before a command is built.

## Why

Describing a configmap prints its data.

## Where

- `K8S_DESCRIBE_RESOURCE_TYPES` and `normalize_k8s_resource_type` in `mcp_ssh.py`
  hold the list and map plural and short names (`pods`, `po`, `deploy`, `svc`)
  to the canonical type.

## Related

- [get_kubectl_describe_pod.md](get_kubectl_describe_pod.md) — environment values
  that `kubectl describe pod` still prints.
