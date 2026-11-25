#!/bin/sh
# Starts the load side of the socket load test, against a VM running server_start.sh.
# Any user; BusyBox (Alpine) or GNU tools.
# Args: SERVER [HELD [CLOSED [SECONDS]]]
# - HELD connections to SERVER:9000 kept open for SECONDS (ESTAB on both sides);
# - CLOSED connections to SERVER:9000 closed after 3 s (CLOSE-WAIT on the server,
#   FIN-WAIT-2 here);
# - 8 wget loops against http://SERVER/ for SECONDS (TIME-WAIT on the server).
S=${1:?usage: client_start.sh SERVER [HELD [CLOSED [SECONDS]]]}
HELD=${2:-200}
CLOSED=${3:-50}
SECS=${4:-240}
D=${TMPDIR:-/tmp}/socket_load
for p in nc timeout wget setsid; do
    command -v $p >/dev/null 2>&1 || { echo "missing $p" >&2; exit 1; }
done
if [ -f "$D/load.pid" ] && kill -0 "$(cat "$D/load.pid")" 2>/dev/null; then
    echo "load already running (pid $(cat "$D/load.pid"))"
    exit 0
fi
mkdir -p "$D"
cat > "$D/load.sh" <<'EOF'
S=$1; HELD=$2; CLOSED=$3; SECS=$4
D=$(dirname "$0")
# session and process group leader (started by setsid): client_stop.sh kills the whole group
echo $$ > "$D/load.pid"
i=0; while [ $i -lt "$HELD" ]; do (sleep "$SECS" | nc "$S" 9000 >/dev/null 2>&1) & i=$((i + 1)); done
i=0; while [ $i -lt "$CLOSED" ]; do timeout 3 nc "$S" 9000 </dev/null >/dev/null 2>&1 & i=$((i + 1)); done
end=$(($(date +%s) + SECS))
j=0; while [ $j -lt 8 ]; do
    (while [ "$(date +%s)" -lt $end ]; do wget -q -O /dev/null "http://$S/"; done) &
    j=$((j + 1))
done
wait
rm -f "$D/load.pid"
EOF
setsid sh "$D/load.sh" "$S" "$HELD" "$CLOSED" "$SECS" >/dev/null 2>&1 </dev/null &
sleep 1
echo "client started: $HELD held, $CLOSED closed, wget for ${SECS}s against $S"
