# get_kubectl_describe on pods: literal environment values are not redacted

Date: 2026-11-10
Status: accepted, open to revision

## Decision

`kubectl describe pod` prints literal environment values from the pod spec (values
that come from secret references are shown only as references). This is not
redacted.

## Why

The output is free text, and parsing it would be fragile.

## Alternative

Build the pod view from `kubectl get pod -o json` and run it through the same
redaction as the crictl inspect tools (see
[get_crictl_inspect.md](get_crictl_inspect.md)), at the cost of losing the events
section that describe appends.

## Consequence

A secret written as a literal `env` value in a pod spec is visible to the agent
through `get_kubectl_describe`.

The same goes for a secret passed as a command-line argument: `kubectl describe pod`
prints each container's `Command` and `Args`.
