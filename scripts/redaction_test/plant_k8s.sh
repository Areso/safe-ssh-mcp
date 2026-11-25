#!/bin/sh
# Plants fake secrets (ZQ<letter><2 digits> markers, see MARKERS in redaction_test.py) in a
# disposable kubeadm cluster. Run as root on a control plane node (kubectl configured there).
# The pod is pinned to this node, so that crictl on it sees the container too.
set -e
NODE=$(hostname)
kubectl create namespace zqleak --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n zqleak create secret generic zq-db --from-literal=ZQX19=ZQN04 \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: leakpod
  namespace: zqleak
spec:
  replicas: 1
  selector: {matchLabels: {app: leakpod}}
  template:
    metadata:
      labels: {app: leakpod}
    spec:
      nodeName: $NODE
      tolerations: [{operator: Exists}]
      containers:
      - name: leak
        image: busybox:1.37
        command: ["sh", "-c"]
        args:
        - 'echo "starting with password=\$DB_PASSWORD"; echo "api_key=\$API_TOKEN"; echo "token ZQN06";
          echo "db url \$DATABASE_URL"; exec sleep 99999'
        - '--password=ZQN05'
        env:
        - {name: DB_PASSWORD, value: ZQN01}
        - {name: MODE, value: ZQN02}
        - {name: DATABASE_URL, value: "postgres://app:ZQN03@db:5432/app"}
        - {name: TLS_KEY, value: "line ZQN07\nline ZQN08"}
        - {name: ZQX18, value: ZQN09}
        - name: API_TOKEN
          valueFrom: {secretKeyRef: {name: zq-db, key: ZQX19}}
        - name: POD_IP
          valueFrom: {fieldRef: {fieldPath: status.podIP}}
YAML
kubectl -n zqleak rollout status deployment/leakpod --timeout=180s
echo planted
