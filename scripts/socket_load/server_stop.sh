#!/bin/sh
# Undoes server_start.sh. Run as root on the same VM.
D=/run/socket_load
if [ -f "$D/leaky.pid" ]; then
    pid=$(cat "$D/leaky.pid")
    kill "$pid" 2>/dev/null
    i=0; while kill -0 "$pid" 2>/dev/null && [ $i -lt 15 ]; do sleep 1; i=$((i + 1)); done
    kill -KILL "$pid" 2>/dev/null
fi
if [ -f "$D/nginx-installed" ]; then
    systemctl stop nginx
    DEBIAN_FRONTEND=noninteractive apt-get -qq purge -y nginx nginx-common >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get -qq autoremove -y >/dev/null 2>&1
elif [ -f "$D/nginx-started" ]; then
    systemctl stop nginx
fi
rm -rf "$D"
sleep 1
echo "server stopped; listening on :80 / :9000: $(ss -tlnH | grep -cE ':(80|9000) ')"
