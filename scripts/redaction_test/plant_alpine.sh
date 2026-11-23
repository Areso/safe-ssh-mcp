#!/bin/sh
# Plants fake secrets (ZQ<letter><2 digits> markers, see MARKERS in redaction_test.py) on a
# disposable Alpine VM. Run as a non-root user with `doas -n` (the root parts use it).
set -e

# the login user's crontab (BusyBox crontab). @XOXB@ becomes the token prefix here, so
# that no token-shaped string is in this file (GitHub push protection blocks it).
sed 's/@XOXB@/xoxb-/g' <<'CRON' | crontab -
DB_PASSWORD=ZQA01
0 2 * * * mysqldump -uroot -pZQA02 app > /tmp/b.sql
*/5 * * * * wget -q --http-password=ZQA03 https://example.com/
0 3 * * * curl -u bk:ZQA04 https://x
0 4 * * * /usr/bin/app --api-key ZQA05
0 5 * * * SSH_KEY=ZQT10 PRIMARY_KEY=ZQX05 /usr/bin/app @XOXB@ZQT11-1234-abcdefghij
0 6 * * * GITHUB_PAT=ZQT12 FOREIGN_KEY=ZQX06 true
CRON

# root's crontab and a periodic script
doas -n sh -c '
grep -q ZQB01 /etc/crontabs/root || cat >> /etc/crontabs/root <<CRON
0 1 * * * PGPASSWORD=ZQB01 pg_dump app
0 2 * * * /usr/bin/app --token=ZQB02
0 3 * * * ftp://user:ZQB03@ftp.example.com/x
CRON
printf "#!/bin/sh\nDB_PASSWORD=ZQB04 /usr/bin/true\n" > /etc/periodic/daily/leakbackup
chmod +x /etc/periodic/daily/leakbackup
logger -p user.err "db password=ZQB05 failed"
sed -i "\\|/mnt/zq|d" /etc/fstab
cat >> /etc/fstab <<FSTAB
//fs.example.com/zq5 /mnt/zq5 cifs username=bob,password=ZQM11,domain=ZQX09,noauto 0 0
//fs.example.com/zq6 /mnt/zq6 cifs user=bob%ZQM12,,ZQM13,nofail 0 0
FSTAB
'

# a busy process with secrets in its arguments, as the login user
pkill -f ZQP1 2>/dev/null || true
nohup nice -n 19 sh -c 'while :; do :; done' busy --password=ZQP11 >/dev/null 2>&1 &
sleep 1
echo planted
