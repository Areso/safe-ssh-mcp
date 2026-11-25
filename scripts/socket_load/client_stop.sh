#!/bin/sh
# Undoes client_start.sh: kills the load's process group. Run as the same user.
D=${TMPDIR:-/tmp}/socket_load
if [ -f "$D/load.pid" ]; then
    pg=$(cat "$D/load.pid")
    kill -TERM -"$pg" 2>/dev/null
    # a few hundred processes take a while to exit on one vCPU
    i=0; while kill -0 -"$pg" 2>/dev/null && [ $i -lt 15 ]; do sleep 1; i=$((i + 1)); done
    kill -KILL -"$pg" 2>/dev/null
fi
rm -rf "$D"
echo "client stopped; nc processes of this user left: $(pgrep -x -u "$(id -u)" nc | wc -l)"
