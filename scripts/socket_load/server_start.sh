#!/bin/sh
# Starts the target side of the socket load test. Run as root on a disposable Debian/Ubuntu VM.
# - nginx on :80 (installed if missing, started if stopped; server_stop.sh undoes only what
#   this script did): the client's wget loops leave TIME-WAIT here.
# - on :9000, a python3 server that accepts connections and never reads or closes them:
#   held connections stay ESTAB, the ones the client closes pile up in CLOSE-WAIT (a leak).
# - in the same process, connections to a blackholed address that stay in SYN-SENT
#   (a dead upstream).
set -e
D=/run/socket_load
mkdir -p "$D"

if ! command -v nginx >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get -qq update >/dev/null
    apt-get -qq install -y nginx >/dev/null
    touch "$D/nginx-installed"
fi
if ! systemctl is-active -q nginx; then
    systemctl start nginx
    touch "$D/nginx-started"
fi

if [ -f "$D/leaky.pid" ] && kill -0 "$(cat "$D/leaky.pid")" 2>/dev/null; then
    echo "leaky server already running (pid $(cat "$D/leaky.pid"))"
else
    cat > "$D/leaky.py" <<'EOF'
# socket load test: see server_start.sh
import socket
import threading
import time

BLACKHOLE = ("10.255.255.1", 5432)
SYN_SENT = 3


def syn_sent():
    while True:
        t = time.time()
        try:
            socket.create_connection(BLACKHOLE, timeout=120).close()
        except OSError:
            pass
        # an unreachable error instead of silence: do not spin
        if time.time() - t < 5:
            time.sleep(5)


for _ in range(SYN_SENT):
    threading.Thread(target=syn_sent, daemon=True).start()

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9000))
s.listen(1024)
keep = []
while True:
    c, _ = s.accept()
    keep.append(c)
EOF
    # not a process group leader when started with &, so setsid execs python3 itself: $! is its pid
    setsid python3 "$D/leaky.py" >/dev/null 2>&1 </dev/null &
    echo $! > "$D/leaky.pid"
fi

sleep 1
ss -tlnH | grep -E ':(80|9000) ' || { echo "nothing listens on :80 / :9000" >&2; exit 1; }
echo "server started"
