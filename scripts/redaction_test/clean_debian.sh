#!/bin/sh
# Removes everything plant_debian.sh created (docker.io itself stays installed). Run as root.
systemctl stop leaktest leakfail 2>/dev/null
rm -rf /etc/systemd/system/leaktest.service /etc/systemd/system/leaktest.service.d \
    /etc/systemd/system/leakfail.service /etc/default/leaktest
systemctl daemon-reload
systemctl reset-failed leakfail leaktest 2>/dev/null
crontab -r 2>/dev/null
crontab -u appuser -r 2>/dev/null
userdel -r appuser 2>/dev/null
rm -f /etc/cron.d/leaktest /etc/cron.d/leaktokens
sed -i '/ZQE01/d' /etc/crontab
sed -i '\|/mnt/zq|d' /etc/fstab
systemctl daemon-reload
pkill -f 'ZQP0' 2>/dev/null
command -v docker >/dev/null 2>&1 && docker rm -f leakdocker >/dev/null 2>&1
# the journal keeps the ZQJ lines until it rotates: journalctl --rotate --vacuum-time=1s clears it
echo cleaned
