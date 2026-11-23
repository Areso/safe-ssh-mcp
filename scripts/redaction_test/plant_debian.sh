#!/bin/sh
# Plants fake secrets (ZQ<letter><2 digits> markers, see MARKERS in redaction_test.py) on a
# disposable Debian/Ubuntu VM. Run as root. SKIP_DOCKER=1 skips installing docker.io.
set -e
# Token prefixes are written as @GHP@, @SKLIVE@, @XOXB@, @AKIA@ and put in place by
# fill_tokens on the VM, so that no token-shaped string is in this file: GitHub push
# protection blocks a push that contains one, fake or not.
fill_tokens() { sed -i 's/@GHP@/ghp_/g; s/@SKLIVE@/sk_live_/g; s/@XOXB@/xoxb-/g; s/@AKIA@/AKIA/g' "$@"; }

# ---- systemd: unit file, drop-ins, environment file ----
cat > /etc/systemd/system/leaktest.service <<'UNIT'
[Unit]
Description=leak test (fake secrets)

[Service]
Type=simple
WorkingDirectory=/tmp
EnvironmentFile=-/etc/default/leaktest
Environment=DB_PASSWORD=ZQU01
Environment="API_TOKEN=ZQU02 ZQU03" "MODE=prod"
Environment='SECRET_KEY=ZQU04'
Environment=MODE=prod DB_PASS=ZQU05 LOG=1
Environment=AMQP_URL=amqp://app:ZQU06@localhost:5672/
Environment=AWS_SECRET_ACCESS_KEY=ZQU07
Environment=GITHUB_PAT=ZQU08
Environment=STRIPE_KEY=@SKLIVE@ZQU09
Environment=MYSQL_PWD=ZQU10
SetCredential=dbpass:ZQU11
ExecStartPre=-/usr/bin/curl -s -m 1 -u admin:ZQU15 -H "Authorization: Bearer ZQU16abcdefgh" http://127.0.0.1:1/
ExecStart=/bin/sh -c 'while :; do sleep 300; done' leaktest --password=ZQU12 --api-key ZQU13 --token=ZQU14
Restart=always

[Install]
WantedBy=multi-user.target
UNIT
mkdir -p /etc/systemd/system/leaktest.service.d
cat > /etc/systemd/system/leaktest.service.d/override.conf <<'UNIT'
[Service]
Environment=REDIS_URL=redis://:ZQU18@localhost:6379/0
Environment="PGPASSWORD=ZQU19"
Environment=DATABASE_URL=postgres://u:ZQU20@db/app
# a comment with password=ZQU21
UNIT
cat > /etc/systemd/system/leaktest.service.d/tokens.conf <<'UNIT'
[Service]
Environment="SLACK_TOKEN_X=1" "STRIPE_KEY=@SKLIVE@ZQT01abcdefgh ijk" "PRIMARY_KEY=id_ZQX01" "PUBLIC_KEY=ZQX02"
Environment=NOTIFY=@XOXB@ZQT02-12345-abcdefghij GH=@GHP@ZQT03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AWS_ID=@AKIA@ZQT04ABCDEFGHIJK
UNIT
cat > /etc/default/leaktest <<'ENV'
DB_PASSWORD=ZQF01
ENV

# a unit that writes secrets to the journal and fails
cat > /etc/systemd/system/leakfail.service <<'UNIT'
[Unit]
Description=leak test that fails (fake secrets in the journal)

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo "connecting with password=ZQJ01 token ZQJ02" >&2; logger -p user.err "db password=ZQJ03 failed"; echo "mysql -uroot -pZQJ04 failed"; exit 1'
UNIT
fill_tokens /etc/systemd/system/leaktest.service /etc/systemd/system/leaktest.service.d/tokens.conf
systemctl daemon-reload
systemctl restart leaktest
systemctl start leakfail || true

# ---- cron: root crontab, /etc/cron.d, /etc/crontab, another user ----
crontab - <<'CRON'
MAILTO=ops@example.com
DB_PASSWORD=ZQC01
0 2 * * * mysqldump -uroot -pZQC02 --all-databases > /backup.sql
*/5 * * * * curl -s -u admin:ZQC03 https://example.com/ping
0 3 * * * PGPASSWORD=ZQC04 pg_dump app
15 * * * * /opt/backup.sh --password ZQC05 --api-key=ZQC06
30 * * * * curl -H "Authorization: Bearer ZQC07abcdefgh" https://x
45 * * * * sshpass -p ZQC08 ssh u@h true
0 4 * * * rsync rsync://bk:ZQC09@backup.example.com/m /data
0 5 * * * sh -c 'DB_PASS=ZQC10 ./run'
0 6 * * * /usr/local/bin/app TOKEN=ZQC11
0 7 * * * mysql -u root --password="ZQC12 with space" -e 'x'
0 8 * * * mysql -h db -p'ZQC13 q' app
0 9 * * * /usr/bin/app --db-password ZQC14
0 10 * * * echo ZQC15 | docker login -u me --password-stdin
0 11 * * * export API_KEY=ZQC16; /usr/bin/ZQX11
CRON
cat > /etc/cron.d/leaktest <<'CRON'
SECRET=ZQD01
* * * * * root /usr/bin/true --secret=ZQD02 >/dev/null
* * * * * root REDIS_PASSWORD=ZQD03 /usr/bin/true
CRON
cat > /etc/cron.d/leaktokens <<'CRON'
* * * * * root /usr/bin/true @GHP@ZQT05bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb @SKLIVE@ZQT06abcdefgh @AKIA@ZQT07ABCDEFGHIJK
* * * * * root MYSQL_PWD=ZQT08 GITHUB_PAT=ZQT09 SORT_KEY=ZQX03 OLDPWD=ZQX04 /usr/bin/true
CRON
fill_tokens /etc/cron.d/leaktokens
grep -q ZQE01 /etc/crontab || echo '17 * * * * root /usr/bin/true --token ZQE01' >> /etc/crontab
id appuser >/dev/null 2>&1 || useradd -m appuser
printf '%s\n' '0 1 * * * export API_KEY=ZQV01; /usr/bin/true' 'MY_PRIVATE_KEY=ZQV02' '5 1 * * * /usr/bin/true' | crontab -u appuser -

# ---- /etc/fstab: cifs passwords (nofail / noauto: a reboot does not wait for them) ----
sed -i '\|/mnt/zq|d' /etc/fstab
cat >> /etc/fstab <<'FSTAB'
//fs.example.com/zq1 /mnt/zq1 cifs username=bob,password=ZQM01,vers=3.0,domain=ZQX07,noauto,nofail 0 0
//fs.example.com/zq2 /mnt/zq2 cifs user=bob%ZQM02,nofail,_netdev 0 0
//fs.example.com/zq3 /mnt/zq3 cifs pass=ZQM03,password2=ZQM04,uid=ZQX08,noauto 0 0
//fs.example.com/zq4 /mnt/zq4 cifs credentials=/etc/cifs-zq.cred,nofail 0 0
//fs.example.com/zq5 /mnt/zq5 cifs username=bob,password=ZQM05,,ZQM06,file_mode=ZQX10,nofail 0 0
FSTAB
systemctl daemon-reload

# ---- processes with secrets in their arguments (nice 19: the busy loop still tops an idle host) ----
pkill -f 'ZQP0' 2>/dev/null || true
nohup nice -n 19 sh -c 'while :; do :; done' busy --password=ZQP01 >/dev/null 2>&1 &
nohup python3 -c 'import time; a = bytearray(150 * 10**6); time.sleep(99999)' --token=ZQP02 >/dev/null 2>&1 &
nohup python3 -c 'import socket, time; s = socket.socket(); s.bind(("0.0.0.0", 8765)); s.listen(); time.sleep(99999)' --password=ZQP03 >/dev/null 2>&1 &

# ---- docker: env, label, command and logs of a container ----
if [ "${SKIP_DOCKER:-}" != 1 ]; then
    if ! command -v docker >/dev/null 2>&1; then
        echo "installing docker.io (a few minutes on a small VM)"
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io >/dev/null
    fi
    docker rm -f leakdocker >/dev/null 2>&1 || true
    docker run -d --name leakdocker -e DB_PASSWORD=ZQK01 -e "API_TOKEN=ZQK02" \
        -e DATABASE_URL=postgres://u:ZQK03@db/app -l "secret=ZQK04" busybox \
        sh -c "echo starting with password=ZQK05; echo token ZQK06 >&2; sleep 99999 --password=ZQK07" >/dev/null
fi
sleep 1
echo planted
