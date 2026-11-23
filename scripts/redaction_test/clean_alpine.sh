#!/bin/sh
# Removes everything plant_alpine.sh created. Run as the same non-root user, with doas -n.
crontab -r 2>/dev/null
doas -n sh -c "sed -i '/ZQB0/d' /etc/crontabs/root; rm -f /etc/periodic/daily/leakbackup; sed -i '\\|/mnt/zq|d' /etc/fstab"
pkill -f 'ZQP1' 2>/dev/null
echo cleaned
