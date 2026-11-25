#!/bin/sh
# Removes everything plant_k8s.sh created. Run as root on the same control plane node.
kubectl delete namespace zqleak --wait=true >/dev/null 2>&1
echo cleaned
