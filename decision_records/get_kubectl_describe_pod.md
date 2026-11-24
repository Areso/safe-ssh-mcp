# get_kubectl_describe: every literal environment value is redacted

Date: 2026-11-10, revised 2026-11-24
Status: accepted

## Decision

`get_kubectl_describe` passes its output through `redact_k8s_describe` (via
`redact_secrets_in_result(result, redactor=redact_k8s_describe)`):

1. In every `Environment:` block (the containers of a pod, and the pod template of a
   deployment, statefulset, daemonset, replicaset, job or cronjob), each literal value is
   replaced by `<redacted>` and the variable name is kept. A multi-line value goes with all
   its continuation lines.
2. References are kept as they are, since they hold no value and say where it comes from:
   `<set to the key 'k' in secret 's'>`, `<set to the key 'k' of config map 'c'>`, field
   references (`(v1:status.podIP)`) and resource references (`node allocatable (limits.cpu)`).
3. The rest of the output goes through `SECRET_PATTERNS`: `Command` and `Args` (where a
   `--password=x` or a connection string is passed), annotations, events.

```
    Args:
      --password=<redacted>
    Environment:
      DB_PASSWORD:   <redacted>
      MODE:          <redacted>
      TLS_KEY:       <redacted>
      API_TOKEN:     <set to the key 'token' in secret 'db'>  Optional: false
      POD_IP:         (v1:status.podIP)
```

## Why

`kubectl describe pod` prints the literal `env` values of the pod spec, which is where
secrets are written when they are not in a Secret. Before 2026-11-24 they were returned
as they are, because parsing free text was thought fragile.

Every value is redacted, not only those whose name sounds secret, as in the crictl inspect
tools ([get_crictl_inspect.md](get_crictl_inspect.md)): a variable's name does not tell
whether its value is a secret, and `SECRET_PATTERNS` alone, tried on real output
(2026-11-24, kubeadm 1.37), left `MODE=x` shown, hid only the first line of a multi-line
value and mangled the reference lines (`<redacted> to the key 'token' ...`). The names
stay: knowing that a variable is set is useful for diagnostics on its own.

The block is easy to find: a line `Environment:` alone, entries indented under it as
`NAME:  value`, continuation lines indented deeper. `Environment:  <none>` (no block) and
`Environment Variables from:` (names of the referenced config maps and secrets) are not
blocks and are left to `SECRET_PATTERNS`.

## Trade-off

- A literal value that is not a secret (`MODE=prod`, `LOG_LEVEL=debug`) is hidden too. Its
  name stays, and the value is in the manifest for whoever can read it.
- `SECRET_PATTERNS` also hides some harmless values in the rest of the output, as it does
  in the ps tools for the same command lines: `TokenExpirationSeconds: <redacted>` of
  projected service account volumes, the apiserver's `--enable-bootstrap-token-auth=` and
  `--tls-private-key-file=` (a path), `$DB_PASSWORD` in a shell script in `Args`.
- A secret in an unusual form in `Command`/`Args` is still shown (`token x` without `=`).

## Alternative

Build the pod view from `kubectl get pod -o json` and redact it like the crictl inspect
tools. Not done: it loses the events and the computed state that describe adds, and
`SECRET_PATTERNS` is still needed for the command line.

## Where

- `redact_k8s_describe`, `_K8S_ENV_HEADER`, `_K8S_ENV_ENTRY`, `_K8S_ENV_REFERENCE` in
  `mcp_ssh.py`.
- Unit tests: `tests/test_redact.py` (`test_describe_*`).
- Live: the `k8s` profile of `scripts/redaction_test/` (markers `ZQN01`-`ZQN09`, controls
  `ZQX18`, `ZQX19`), 2026-11-24 on a kubeadm 1.37 cluster: all hidden, controls shown.

## Related

- [get_kubectl_describe.md](get_kubectl_describe.md): secrets and configmaps cannot be
  described at all.
- The logs and events of the same pods are redacted with `SECRET_PATTERNS`
  (`get_kubectl_logs`, `get_crictl_logs`, `get_kubectl_events`); see
  [redact_secrets.md](redact_secrets.md).
