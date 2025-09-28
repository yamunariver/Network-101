sysctl -w net.ipv4.ip_forward=1 — enable IPv4 forwarding.
sysctl -w net.ipv6.conf.all.forwarding=1 — enable IPv6 forwarding.
ip link set dev eth0 up — bring interface up.
ip addr add 10.0.0.1/24 dev eth0 — assign IP to interface.
ip route add 0.0.0.0/0 via 10.0.0.254 — set default route.
ip rule add from 10.0.0.2 table 100 — policy routing by source.
ip route add table 100 default via 10.0.0.254 — route table for policy.
ss -tunaep — show sockets, processes and programs.
ss -s — summary of socket usage.
tcpdump -i eth0 -w capture.pcap — capture traffic to file.
tcpdump -i eth0 'tcp port 80 and host 10.0.0.5' — filtered capture.
tshark -r capture.pcap -T fields -e ip.src -e ip.dst — extract fields.
wireshark capture.pcap — GUI packet analysis.
tcpdump -ttt -n -vvv -r capture.pcap — human-friendly timestamps and verbose.
tcpdump -i any -s 0 -w - | wireshark -k -S -i - — live piped to Wireshark.
ip neigh show — show ARP/ND table.
arping -I eth0 -c 3 10.0.0.1 — test ARP reachability.
ip route get 8.8.8.8 — show route resolution for destination.
traceroute -n 8.8.8.8 — trace path without DNS lookups.
mtr --report 8.8.8.8 — combined traceroute/ping report.
iperf3 -s — run iperf3 server for bandwidth tests.
iperf3 -c server -P 10 -t 60 — parallel streams for stress tests.
ethtool eth0 — show link and features.
ethtool -S eth0 — show NIC stats.
ethtool -K eth0 tso off gso off gro off — disable offloads for tcpdump accuracy.
ethtool -s eth0 speed 1000 duplex full autoneg off — set fixed link speed.
tc qdisc add dev eth0 root fq_codel — install fq_codel qdisc.
tc qdisc add dev eth0 root handle 1: htb default 12 — create HTB root qdisc.
tc class add dev eth0 parent 1: classid 1:1 htb rate 1gbit — HTB class.
tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip dst 10.0.0.0/24 flowid 1:1 — traffic classing.
tc qdisc add dev ifb0 ingress — setup IFB for ingress shaping.
ip link add veth0 type veth peer name veth1 — create veth pair.
ip netns add ns1 — create network namespace.
ip link set veth1 netns ns1 — move veth into namespace.
ip netns exec ns1 ip addr add 192.168.1.2/24 dev veth1 — configure in namespace.
ip netns exec ns1 ip link set veth1 up — bring namespace interface up.
ip netns exec ns1 ping -c 3 192.168.1.1 — execute ping inside namespace.
bridge link — show Linux bridge ports.
ip link add name br0 type bridge — create bridge.
ip link set dev br0 up — enable bridge.
ip addr add 10.10.10.1/24 dev br0 — SVI-like on Linux bridge.
bridge vlan add vid 10 dev eth1 pvid untagged — assign VLAN to bridge port.
vconfig add eth0 100 — (deprecated) create VLAN subinterface.
ip link add link eth0 name eth0.100 type vlan id 100 — create VLAN subinterface modern.
bridge fdb add 00:11:22:33:44:55 dev br0 — add static L2 entry.
bridge fdb show — show forwarding database.
bridge vlan show — show VLAN mapping on bridge.
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE — NAT for private network.
iptables -A FORWARD -i br0 -o eth0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT — allow established forwarding.
iptables -A FORWARD -i eth0 -o br0 -j ACCEPT — allow forwarding to internal.
iptables -t raw -I PREROUTING -j NOTRACK — bypass conntrack for performance.
conntrack -L | wc -l — count conntrack table entries.
conntrack -F — flush conntrack table.
sysctl -w net.netfilter.nf_conntrack_max=524288 — scale conntrack size.
nft add table inet filter — create nftables table.
nft add chain inet filter input { type filter hook input priority 0; } — nft input chain.
nft add rule inet filter input ip saddr 1.2.3.4 drop — nft rule to drop IP.
nft list ruleset — show nftables ruleset.
iptables-save > /root/iptables.pre — backup iptables rules.
iptables-restore < /root/iptables.pre — restore iptables.
sysctl -w net.ipv4.tcp_tw_reuse=1 — reuse TIME_WAIT sockets.
sysctl -w net.ipv4.tcp_tw_recycle=0 — keep recycle disabled (broken).
sysctl -w net.ipv4.tcp_fin_timeout=15 — shorten FIN timeout.
ss -o state established '( dport = :http or sport = :http )' — list HTTP connections.
ss -o 'state established and ( sport = :ssh or dport = :ssh )' — SSH connections active.
lsof -iTCP -sTCP:LISTEN -P -n — list listening TCP sockets.
fuser -n tcp 80 — show PIDs using port 80.
kill -USR1 $(cat /var/run/nginx.pid) — reload Nginx gracefully.
systemctl daemon-reload — reload systemd units.
systemctl restart networking — restart network service.
journalctl -u sshd -b — view sshd logs since boot.
journalctl -k -b — kernel messages since boot.
journalctl -f -u systemd-resolved — follow DNS resolver logs.
journalctl --since '2025-01-01' --until '2025-01-02' — date range logs.
dmesg -T | tail -n 200 — last kernel messages human time.
echo c > /proc/sysrq-trigger — trigger immediate crash dump (use with care).
kdumpctl show — show kdump status (on distros with kexec-tools).
crash /usr/lib/debug/vmlinux vmcore — analyze kernel crash dump.
perf record -F 99 -a -g -- sleep 30 — collect perf samples system-wide.
perf report --call-graph — analyze perf recording.
perf top — live profiling.
perf script | ./FlameGraph/stackcollapse-perf.pl | ./FlameGraph/flamegraph.pl > perf.svg — create flamegraph.
bpftrace -e 'kprobe:sys_clone { @[comm] = count(); }' — count clone calls per command.
bpftrace -l — list bpftrace probes.
bpftool prog — list BPF programs.
bpftool map — list BPF maps.
tc qdisc add dev eth0 clsact — add clsact qdisc for tc-bpf.
tc filter add dev eth0 ingress bpf da obj prog.o sec classifier — attach BPF to ingress.
ipvsadm -L -n — list Linux LVS/IPVS virtual servers.
ipvsadm -A -t 10.0.0.1:80 -s rr — add IPVS virtual service round-robin.
ipvsadm -a -t 10.0.0.1:80 -r 10.0.0.11:80 -g — add real server with NAT.
keepalived -V — show keepalived version and config test.
vipaddr — (concept) apply virtual IP for HA.
haproxy -c -f /etc/haproxy/haproxy.cfg — config check.
ss -n sport = :80 — show sockets bound to port 80.
ngrep -d eth0 'GET ' tcp and port 80 — grep HTTP requests live.
socat -d -d TCP-LISTEN:9000,reuseaddr,fork TCP:example.com:80 — forward ports.
socat UNIX-LISTEN:/tmp/foo,perm=666,reuseaddr,fork SYSTEM:'bash -s' — unix socket to shell.
nc -l -p 12345 — simple TCP listener.
nc -zv host 22 — port scan with netcat.
strace -f -p <pid> — attach to process syscalls trace.
strace -o /tmp/trace -ff -p <pid> — record into files per thread.
ltrace -p <pid> — trace library calls.
gdb -p <pid> — attach gdb live.
gdb --args ./binary arg1 — debug program with args.
pmap -x <pid> — memory map of process.
smem -rt — show memory usage per process accurately.
top -o %MEM — sort top by memory.
htop — interactive process viewer.
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 30 — top CPU consumers.
nice -n 19 command — run with low priority.
renice -n -10 -p <pid> — increase process priority.
ionice -c2 -n7 -p <pid> — set IO priority best-effort.
blkid /dev/sda1 — show filesystem UUID and type.
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,UUID — block device tree.
udevadm info --query=all --name=/dev/sda — udev info.
parted -l — show partition table details.
sgdisk -p /dev/sda — GPT layout print.
mdadm --detail /dev/md0 — show software RAID details.
mdadm --assemble --scan — assemble all arrays.
mdadm --manage /dev/md0 --add /dev/sdb1 — add disk to RAID.
xfs_repair /dev/sdb1 — repair XFS filesystem (unmount first).
xfs_admin -L newlabel /dev/sdb1 — change XFS label.
tune2fs -c 0 -i 0 /dev/sda1 — disable e2fs periodic checks.
resize2fs /dev/sda1 50G — grow ext4 filesystem (after block resize).
mount -o remount,ro /mountpoint — remount read-only for safety.
umount -l /mnt — lazy unmount (use with caution).
losetup -f --show /path/image — map loop device.
cryptsetup luksOpen /dev/sdb1 secure — open LUKS container.
cryptsetup status secure — check LUKS status.
pvcreate /dev/sdb1 — create LVM PV.
vgcreate vgdata /dev/sdb1 — create volume group.
lvcreate -n lvdata -L 100G vgdata — create logical volume.
mkfs.ext4 /dev/vgdata/lvdata — format LV ext4.
mount /dev/vgdata/lvdata /data — mount LV.
lvextend -L +50G /dev/vgdata/lvdata — extend LV.
pvs -o+pv_used — show PV usage.
vgs — show VG summary.
lvs -a -o +devices — show LV devices.
btrfs filesystem df /mnt — show btrfs usage.
btrfs scrub start -Bd /mnt — scrub btrfs for errors.
btrfs balance start -d -mconvert=raid1 /mnt — balance/convert RAID level.
rsync -aHAX --delete --numeric-ids src/ dst/ — robust file sync preserving attributes.
rsync --inplace --no-whole-file — efficient large-file sync.
tar -czf backup.tgz --acls --xattrs /etc — tar preserving ACLs and xattrs.
star -c -x — use star for advanced tar features (if installed).
restic init -r /backup/repo — initialize restic repo.
restic backup /data -r /backup/repo — restic backup.
borg init --encryption=repokey-blake2 repo — init borg backup.
borg create repo::'{hostname}-{now}' /data — borg backup create.
dd if=/dev/zero of=/tmp/testfile bs=1M count=1024 oflag=direct — raw write test.
fio --name=randrw --rw=randrw --bs=4k --size=1G --runtime=60 --iodepth=32 — IO performance test.
iostat -x 1 — detailed IO stats per device.
iostat -xz 1 — extended with CPU.
blktrace -d /dev/sda -o - | blkparse -i - — block IO tracing.
strace -e trace=network -p <pid> — trace only network syscalls.
ss -m — show memory usage per socket.
grep -i oom /var/log/kern.log — search for OOM killer kills.
echo 1 > /proc/sys/vm/overcommit_memory — strict overcommit.
echo 0 > /proc/sys/vm/zone_reclaim_mode — disable zone reclaim.
sysctl -w vm.swappiness=10 — bias away from swapping.
sysctl -w vm.dirty_ratio=15 — dirty pages ratio.
sysctl -w vm.dirty_background_ratio=5 — background flush threshold.
sysctl -w vm.min_free_kbytes=65536 — reserve free memory.
ulimit -n 65536 — increase per-shell FD limit.
cat /proc/sys/fs/file-nr — show file handles usage.
echo 1000000 > /proc/sys/fs/file-max — increase global file limit.
systemctl set-property --runtime sshd.service TasksMax=20000 — adjust systemd cgroup tasks for unit.
systemctl set-property --runtime sshd.service MemoryMax=1G — cap unit memory.
systemd-run --scope -p MemoryLimit=500M /bin/bash — run process in limited scope.
systemd-cgtop — top for control groups.
systemd-analyze blame — slow units at boot.
systemd-analyze plot > boot.svg — boot sequence graph.
journalctl --vacuum-size=500M — trim journal size.
auditctl -w /etc/ssh/sshd_config -p wa -k sshd_change — audit SSH config changes.
ausearch -k sshd_change — search audit logs for key.
aureport -f — generate file access summary.
semanage fcontext -a -t httpd_sys_content_t '/var/www(/.*)?' — SELinux file context.
restorecon -Rv /var/www — relabel SELinux files.
getenforce — SELinux status.
setenforce 0 — temporarily set SELinux permissive.
ausearch -m AVC -ts recent — search SELinux AVC denials.
semodule -l — list SELinux modules.
sepolicy generate --type httpd — aid SELinux policy creation (tooling varies).
aa-status — AppArmor status.
aa-complain /etc/apparmor.d/usr.bin.mysvc — set profile to complain.
aa-enforce /etc/apparmor.d/usr.bin.mysvc — enforce profile.
getfattr -d -m - /path — list extended attributes.
setfattr -n user.test -v val /path — set xattr.
truncate -s 0 /var/log/huge.log — zero big log file safely.
rsyslogd -N1 — config syntax check for rsyslog.
nginx -t — test nginx config.
apachectl -t — test apache config.
mysqladmin ping — check MySQL up.
mysql -e 'SHOW PROCESSLIST\G' — show mysql connections.
pg_isready -h host -p 5432 — Postgres readiness check.
psql -c 'SELECT pid, state FROM pg_stat_activity;' — Postgres process states.
redis-cli INFO clients — Redis client info.
redis-cli MONITOR — live Redis command stream (dangerous).
sshd -T | grep -i ciphers — runtime sshd config dump.
openssl s_client -connect host:443 -servername host — test TLS handshake SNI.
openssl x509 -in cert.pem -text -noout — display certificate details.
openssl s_client -showcerts -connect host:443 — show remote cert chain.
nmap -sS -p- -T4 target — full TCP port scan.
nmap -sU -p U:53,123 target — UDP port scan selective.
nmap -A target — aggressive service detection.
masscan -p1-65535 --rate=10000 target — huge-scale port scan (careful).
docker ps -a --format '{{.ID}} {{.Names}} {{.Status}}' — docker container summary.
docker inspect --format '{{json .NetworkSettings}}' container — dump networking settings.
docker network ls — list docker networks.
docker network inspect bridge — inspect bridge network.
docker run --net=host ... — host networking mode.
docker run --cap-add=NET_ADMIN ... — grant container NET_ADMIN capability.
docker exec -it container ip addr — run ip inside container.
ctr t ls — list containerd tasks (containerd CLI).
crictl ps -a — list pods/containers for CRI.
kubectl get pods -A -o wide — list all pods across namespaces.
kubectl describe pod podname — detailed pod info.
kubectl logs -f podname -c container — follow container logs.
kubectl exec -it pod -- /bin/sh — exec into pod.
kubectl port-forward svc/myservice 8080:80 — forward port to service.
kubectl apply -f manifest.yaml --record — apply config and record change.
kubectl get events --sort-by='.metadata.creationTimestamp' — recent events.
kubectl top pod -A — resource usage (metrics-server needed).
kubectl cp pod:/path /localpath — copy files from pod.
kubectl run -it --rm debug --image=networkstatic/iperf3 --restart=Never -- iperf3 -s — ephemeral debug pod.
kubectl get csr — check certificate signing requests for kubelet.
kubectl auth can-i create deployments --as system:serviceaccount:default:sa — test RBAC.
kubectl edit cm kube-proxy -n kube-system — edit kube-proxy configmap.
kubeadm token list — list tokens for join.
kubeadm reset — reset kubeadm cluster state.
helm repo add stable https://charts.helm.sh/stable — add helm repo.
helm install --create-namespace myapp stable/chart — install helm chart.
calicoctl get bgppeers — calico BGP peer config (if using Calico).
cilium status — Cilium agent status for eBPF networking.
ip a show dev cni0 — inspect CNI bridge interfaces.
ip link set dev cni0 up — bring CNI bridge up.
bridge vlan show dev cni0 — show VLANs on CNI bridge.
kubectl apply -f calico.yaml — deploy Calico CNI.
kubectl describe netpol netpol-name — show network policy.
iptables -t nat -L KUBE-SERVICES -n --line-numbers — inspect kube-proxy chains.
ipvsadm -L --exact — view IPVS entries (kube-proxy IPVS mode).
etcdctl --endpoints=https://10.0.0.1:2379 --cert=... member list — etcd members.
etcdctl snapshot save snapshot.db — take etcd snapshot.
etcdctl snapshot status snapshot.db — snapshot metadata.
curl -sS --cacert ca.crt --cert client.crt --key client.key https://127.0.0.1:2379/metrics — etcd metrics.
quagga/bgpd — (concept) run BGP daemon on Linux (use FRR).
apt install frr — install FRRouting on Debian-based.
vtysh -c 'show ip bgp summary' — FRR BGP summary.
vtysh -c 'show ip route' — FRR routing table.
ip vrf add red — create VRF instance.
ip link add red-veth type veth peer name red-br — create veth for VRF.
ip link set red-br master br-red — attach to bridge in VRF.
ip route add vrf red 10.1.1.0/24 via 192.168.0.1 — VRF-specific route.
ip netns exec vrfns ip route — view netns-specific routes.
ip rule add fwmark 1 table 200 — policy route based on mark.
iptables -t mangle -A PREROUTING -j MARK --set-mark 1 — set fwmark in mangle.
ip -s link — show interface statistics.
ifstat -i eth0 1 — per-interface throughput.
nstat — network stack stats.
netstat -rn — legacy routing table.
route -n — older route display.
ip monitor all — watch IP changes live.
watch -n1 'ip route show' — live watch route table.
watch -n1 'ss -s' — watch socket summary.
watch -n1 'cat /proc/net/snmp' — watch snmp counters.
grep -i retransmiss /proc/net/netstat — check TCP retransmits counters.
tc -s qdisc — show qdisc stats.
tc -s class show dev eth0 — class stats.
tc -s filter show dev eth0 — filter stats.
tc filter show dev eth0 parent 1: — show specific filter.
tc qdisc del dev eth0 root — remove qdisc.
tc qdisc show dev eth0 — list qdiscs.
tc qdisc add dev eth0 root netem delay 100ms loss 1% — simulate latency and loss.
tc qdisc add dev eth0 root handle 1: netem delay 50ms — netem base delay.
tc qdisc add dev eth0 parent 1:1 handle 10: tbf rate 10mbit burst 32k latency 50ms — TBF shaping.
tc filter add dev eth0 parent 1:0 protocol ip prio 1 u32 match ip dst 10.0.0.0/24 flowid 1:1 — u32 match.
tc flower add dev eth0 protocol ip flower dst_ip 10.0.0.1 action mirred egress redirect dev eth1 — flower mirror redirect.
tc monitor — monitor tc events.
iptables -t mangle -A PREROUTING -p tcp --dport 80 -j TOS --set-tos 0x10 — set TOS for QoS.
ip route replace default via 10.0.0.254 dev eth0 metric 10 — replace route atomically.
ip route del 10.0.0.0/24 via 192.168.0.1 — delete route.
ip link set eth0 promisc on — enable promiscuous mode.
iwconfig — wireless config (legacy).
iw dev wlan0 scan | egrep 'SSID|signal' — scan SSIDs with signal.
hostapd_cli -i wlan0 status — hostapd status.
wpa_cli -i wlan0 status — WPA supplicant status.
ipset create blacklist hash:ip family inet hashsize 1024 — create ipset for blacklisting.
ipset add blacklist 1.2.3.4 — add entry to ipset.
iptables -I INPUT -m set --match-set blacklist src -j DROP — use ipset in iptables.
nft add element inet myset { 10.0.0.1 } — add to nft set.
nft add rule inet filter input ip saddr @myset drop — use nft set in rule.
watch -n1 'nft list ruleset' — live nft ruleset watch.
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080 — redirect to another local port.
ss -tulpn | grep :80 — find process listening on port 80.
fallocate -l 10G /mnt/test.img — allocate large file quickly.
truncate -s 0 /tmp/file — shrink file to zero.
hdparm -tT /dev/sda — basic disk throughput tests.
smartctl -a /dev/sda — SMART disk details.
smartctl -t long /dev/sda — start extended self-test.
nvme list — list NVMe devices.
nvme smart-log /dev/nvme0 — NVMe health.
nvme rescan — rescan NVMe devices.
udevadm settle --timeout=30 — wait for udev rules.
udevadm trigger --action=add — trigger udev events.
udevadm test /sys/class/net/eth0 — test udev rules for device.
systemd-resolve --status — systemd-resolved DNS details.
resolvectl status — modern DNS resolver status.
dig +noall +answer @8.8.8.8 example.com A — DNS A query direct to server.
dig +short txt _acme-challenge.example.com — check acme challenge TXT.
host -t SRV _sip._tcp.example.com — query SRV record.
ss -4atun sport = :domain — DNS sockets.
tcpdump -n -s 0 -A port 53 — view DNS payloads.
systemd-resolve --flush-caches — flush resolver cache.
resolvectl flush-caches — flush caches new command.
chronyc sources -v — show chrony time sources.
chronyc tracking — chrony tracking info.
timedatectl status — time status.
ntpq -p — query NTP peers (ntp).
chronyd -q 'server ntp.example iburst' — one-shot chrony sync.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out key.pem — generate RSA key.
openssl req -new -key key.pem -out csr.pem — create CSR.
openssl x509 -req -in csr.pem -signkey key.pem -days 365 -out cert.pem — self-sign cert.
sslyze --regular example.com:443 — SSL/TLS scan (if installed).
nginx -s reopen — reopen logs without restart.
systemctl kill --kill-who=main --signal=SIGUSR1 nginx — graceful signal alternative.
haproxy -f /etc/haproxy/haproxy.cfg -D — start haproxy in daemon mode.
haproxy -c -f /etc/haproxy/haproxy.cfg — check config.
sosreport — collect system diagnostics package (RHEL).
dstat -cdlmnpsy — combined system stats live.
collectl -sZ — full-stack performance monitor.
netdata — realtime monitoring daemon (start and view UI).
prometheus --config.file=prometheus.yml — run Prometheus server.
node_exporter --collector.filesystem.ignored-mount-points='^/(sys|proc|dev)' — run node_exporter.
cadvisor — container metrics collector.
grafana-cli plugins install grafana-piechart-panel — extend Grafana (example).
kubectl top nodes — k8s node resource usage.
promtool check config prometheus.yml — validate Prometheus config.
alertmanager --config.file=alertmanager.yml — start Alertmanager.
systemctl restart rsyslog — restart syslog service.
logger -p user.err 'Test alert' — send test syslog message.
sestatus — SELinux status (RedHat).
getenforce — SELinux mode quick check.
setsebool -P httpd_can_network_connect 1 — persist SELinux boolean.
auditctl -l — list audit rules.
ausearch -m USER_LOGIN -ts today — today's user logins.
last -n 50 — show recent logins.
lastlog -u username — show last login for user.
getent passwd — list passwd entries (including LDAP).
id username — show uid/gid and groups.
chage -l username — password expiry info.
pam_tally2 --user username — view failed login count (if installed).
faillog -u username — view failed login records.
sssd -i — start sssd in foreground for debug.
realm list — show joined realm info (sssd/realmd).
kinit user — obtain Kerberos ticket.
klist — list Kerberos tickets.
kdestroy — destroy tickets.
openssl s_client -connect ldap:636 -showcerts — test LDAPS.
ldapsearch -x -H ldap://ldap.example -b dc=example,dc=com '(uid=user)' — simple LDAP query.
nslcd — name service LDAP daemon (varies).
getfacl /path — display POSIX ACLs.
setfacl -m u:alice:rwx /path — give user ACL perms.
setfacl -b /path — remove all ACLs.
usermod -aG docker username — add user to group.
newgrp docker — re-evaluate group without logout.
sudo -l -U username — show sudo privileges.
visudo — edit sudoers safely.
ssh -o PreferredAuthentications=publickey -i key user@host — force publickey auth only.
ssh -o ProxyCommand='nc -X 5 -x proxy:1080 %h %p' host — SSH via socks proxy.
ssh -J jumpuser@jumphost target — SSH jump host (ProxyJump).
ssh -L 8080:localhost:80 remote — local port forwarding.
ssh -R 2222:localhost:22 remote — remote port forwarding.
sshd -D -T — debug SSHD config dump in foreground.
ssh-keygen -t ed25519 -a 100 — generate modern SSH key with rounds.
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@host — copy pubkey to host.
scp -3 src@a:/file dest@b:/file — server-to-server scp via client.
rsync -azP -e 'ssh -p 2222' /src user@host:/dst — rsync over ssh with progress.
sftp user@host — interactive SFTP.
openssl s_client -starttls smtp -connect mail:25 — SMTP STARTTLS test.
swaks --to user@example.com --server mail.example — SMTP test (if installed).
postfix flush — flush postfix mail queue.
postqueue -p — show mail queue.
exim -bp — show exim mail queue.
mailq — generic mail queue.
ssmtp — simple sendmail client (deprecated on many distros).
fail2ban-client status — show fail2ban jail status.
fail2ban-client set sshd unbanip 1.2.3.4 — unban ip.
ufw status numbered — UFW status with numbers.
ufw allow proto tcp from 1.2.3.4 to any port 22 — allow single IP.
firewall-cmd --permanent --add-service=http — add service in firewalld.
firewall-cmd --reload — apply firewalld changes.
nmcli device status — NetworkManager device summary.
nmcli connection show — show NM connections.
nmcli connection up id 'Wired connection 1' — bring up connection.
nmcli device wifi rescan — rescan Wi-Fi.
nmcli device wifi list — list Wi-Fi APs.
connmanctl services — list connman services (if used).
ipset list — show ipset contents.
ufw logging on — enable UFW logging.
tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0' — capture SYN packets.
tcpdump -i eth0 'tcp[tcpflags] & (tcp-rst) != 0' — capture RSTs.
tcpdump -i eth0 'tcp[13] & 2 != 0 and tcp[13] & 16 != 0' — SYN+ACK filter.
iptables -t raw -A PREROUTING -p tcp --dport 22 -j NOTRACK — bypass conntrack for SSH.
ss -K dst 10.0.0.1 dport = :80 — kill connection (newer ss).
conntrack -D -s 1.2.3.4 — delete conntrack entries for source.
ipset -A blacklist 1.2.3.4 — add to ipset blacklist.
nft add meta skgid 100 accept — nft example using skgid.
iptables -I INPUT 1 -m conntrack --ctstate INVALID -j DROP — drop invalid packets.
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT — allow established.
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH — track new SSH.
iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP — simple rate limit.
nft add rule inet filter input tcp dport 22 ct state new limit rate 3/second drop — nft rate limit.
cat /proc/net/netstat — raw netstat counters from kernel.
ip -s -s neigh flush all — flush ARP with stats.
bridge link set dev eth1 learning off — disable learning on bridge port.
bridge link set dev eth1 hairpin on — enable hairpin for bridging veth.
arp -n — legacy ARP table.
ip -4 route show table all — show all IP tables.
ip -6 route show table all — IPv6 route tables.
sysctl -a | grep net.ipv4.tcp — dump TCP sysctl knobs.
sysctl -w net.ipv4.tcp_congestion_control=bbr — set TCP CC algorithm.
sysctl net.core.default_qdisc=fq — change default qdisc to fq.
ss -i dst 1.2.3.4 — in-depth info about connections to dest.
ss -K src 1.2.3.4 — kill sockets by source.
iptables -t mangle -A PREROUTING -p tcp -j TCPMSS --clamp-mss-to-pmtu — clamp MSS for PMTU.
ip6tables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu — IPv6 MSS clamp.
sysctl -w net.ipv4.tcp_mtu_probing=1 — enable MTU probing.
ping -M do -s 1472 host — test PMTU.
tracepath -n host — MTU discovery tracepath.
set -o pipefail — ensure pipeline fails on any error in scripts.
bash -x ./script.sh — debug shell script trace.
shellcheck script.sh — lint shell script (if installed).
awk 'length($0)>200 {print NR,$0}' file — find long lines in file.
sed -n '1,200p' file — print first 200 lines.
grep -R --line-number --binary-files=without-match 'pattern' /etc — recursive config search.
ag --hidden -g '' | xargs sed -n '1,3p' — ripgrep and display snippets (if ag installed).
strace -c -p <pid> — count syscall usage.
perf record -g -p <pid> — profile running process.
perf report --stdio — console perf report.
gcore <pid> — dump process core without killing.
eu-stack -p <pid> — show stack of process using elfutils (if installed).
readelf -a /proc/<pid>/exe — inspect executable details.
ldd /usr/bin/program — list shared libs.
ldconfig -p | grep libssl — show libssl versions.
patchelf --print-rpath /usr/bin/program — check rpath (if patchelf installed).
tcpdump -i eth0 -w - 'port 80' | pv -b > /tmp/cap.pcap — capture with progress.
split -b 100M capture.pcap cap.part. — split large capture into parts.
mergecap -w merged.pcap cap.part.* — merge pcap pieces.
editcap -F pcapng capture.pcap out.pcap — convert pcap format.
tcptraceroute host 80 — TCP-based traceroute.
hping3 --syn -p 80 -c 10 host — craft SYN packets.
hping3 --udp -p 53 -c 10 host — craft UDP packets.
scapy — interactive packet crafting (python).
python -c "import scapy.all as s; s.sniff(count=10,iface='eth0').summary()" — scapy capture snippet.
iptables -N LOGDROP — create custom chain.
iptables -A LOGDROP -m limit --limit 2/min -j LOG --log-prefix 'DROP: ' --log-level 4 — log drops rate-limited.
iptables -A LOGDROP -j DROP — send to drop.
iptables -I INPUT -s 1.2.3.4 -j LOGDROP — use custom chain for IP.
nft add chain inet filter forward { type filter hook forward priority 0 ; } — nft forward chain.
nft add rule inet filter forward ip saddr 10.0.0.0/8 counter accept — nft rule with counter.
nft list ruleset -a — list ruleset with handles.
nft delete rule inet filter forward handle 5 — delete rule by handle.
iptables -t nat -A PREROUTING -p tcp --dport 8443 -j DNAT --to-destination 10.0.0.5:443 — DNAT port redirect.
iptables -t nat -I POSTROUTING -s 10.0.0.5 -j SNAT --to-source 1.2.3.4 — SNAT specific source.
iptables -t mangle -A PREROUTING -p tcp -j MARK --set-mark 0x1 — mark packets for policy routing.
ip rule add fwmark 0x1 table 150 — route marked packets via table.
iptables -I INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT — allow ping.
iptables -I INPUT -p icmp -j DROP — block all ICMP (not recommended).
sysctl -w net.ipv4.conf.all.accept_redirects=0 — disable ICMP redirects.
sysctl -w net.ipv4.conf.all.send_redirects=0 — disable sending redirects.
sysctl -w net.ipv4.conf.all.rp_filter=1 — enable reverse path filter.
echo 1 > /proc/sys/net/ipv4/conf/eth0/accept_source_route — enable source routing (dangerous).
ipvsadm -Ln --stats — IPVS statistics numeric.
ipset -L -n — list all ipsets name-only.
udevadm monitor --kernel --property — monitor udev events while plugging devices.
lsmod | grep ^<module> — check module loaded.
modprobe --show-depends nf_conntrack — show dependencies for module.
modprobe -r iptable_nat — remove kernel module (if unused).
echo 0 > /sys/module/ipv6/parameters/disable — enable/disable IPv6 module parameter.
modinfo e1000e — show NIC driver info.
watch -n 1 'cat /proc/net/dev | sed 1,2d' — live net dev stats watch.
ip link set dev eth0 address 02:ab:cd:ef:12:34 — change MAC address.
ethtool -p eth0 10 — blink NIC LED for 10s (if supported).
tcpdump -i eth0 -G 60 -w capture-%Y%m%d%H%M%S.pcap -W 24 — rotate capture files hourly.
ulogd — userspace netfilter logging daemon.
ngrep -d any -q 'password' — quick grep in network streams.
strings /usr/lib/libcrypto.so | grep -i tls — glance at lib symbols.
objdump -d /usr/sbin/sshd | less — disassemble (advanced debugging).
ldd --version — glibc version check.
journalctl -u systemd-networkd -o json-pretty — JSON formatted logs.
systemd-run --wait --property=CPUQuota=50% stress --cpu 4 — run stress within quota.
stress-ng --cpu 4 --io 2 --vm 1 --vm-bytes 128M --timeout 60s — stress test system.
cgroups v2: echo "+cpu" > /sys/fs/cgroup/unified/cgroup.subtree_control — enable cpu controller (example).
systemd-run --unit=test -p MemoryHigh=200M /bin/sh -c 'dd if=/dev/zero of=/dev/shm/x bs=1M count=500' — test memory pressure.
watch -n1 'cat /proc/vmstat' — watch vm statistics.
cat /proc/slabinfo | sort -k3 -n -r | head — big slab caches.
echo 1 > /proc/sys/vm/drop_caches — free pagecache (use carefully).
swapoff -a && swapon -a — reset swap usage.
cat /proc/interrupts — show IRQ distribution.
irqbalance --debug — start irqbalance debugging.
echo 3 > /proc/sys/vm/panic_on_oom — panic on OOM (for debugging).
systemctl mask systemd-resolved — mask unit to prevent start.
systemctl unmask nginx — reverse mask.
systemctl preset-all — reset units to preset defaults.
useradd -r -s /sbin/nologin -M svcuser — create system user without home.
chpst -u user:group -c 500:500 program — run program under different ulimits (daemontools).
start-stop-daemon --start --exec /usr/bin/prog --chuid user — start daemon as user (Debian-style).
openssl rand -hex 32 — generate random token.
gpg --gen-key — create GPG key for signing.
gpg --list-secret-keys --keyid-format LONG — list secret keys.
sops -e secrets.yaml > secrets.enc — encrypt secrets file (if sops installed).
kubectl create secret generic tls --from-file=tls.crt=./cert.pem --from-file=tls.key=./key.pem — create k8s secret.
kubectl get endpoints -o wide — service endpoints detail.
ipvsadm -Ln --stats | awk '/^TCP/ {print; exit}' — quick IPVS stats parse.
ss -o state time-wait — list TIME-WAIT sockets.
sysctl -w net.ipv4.tcp_max_syn_backlog=2048 — raise SYN backlog.
sysctl -w net.core.somaxconn=1024 — increase listen backlog.
echo 0 > /proc/sys/net/ipv4/tcp_syncookies — toggle syncookies (use with care).
iptables -t raw -A PREROUTING -p tcp --syn -j CT --notrack — example ct notrack (rare).
ss -m — show memory per socket again (reminder).
systemd-run --scope -p CPUAccounting=yes sleep 10 — test cpu accounting.
cat /sys/class/net/eth0/queues/rx-0/rps_cpus — see RPS cpumask.
echo 2 > /sys/class/net/eth0/queues/rx-0/rps_cpus — set RPS cpumask numeric (example).
ethtool -L eth0 combined 8 — set NIC RSS queue count (if supported).
modprobe ixgbe max_vfs=8 — enable SR-IOV virtual functions for driver.
lspci -vvv -s 00:19.0 — verbose pci device info.
bridge link set dev eth0 src 02:00:00:00:00:01 — spoof mac on bridge port (if needed).
ip vrf exec blue ping -I blue-lo 10.1.1.1 — VRF-specific ping.
ip -d link show — detailed link info.
ip -s -d link show bond0 — bond interface stats and detail.
cat /proc/net/bonding/bond0 — bonding mode and slaves.
nmcli connection modify bond0 802-3-ethernet.cloned-mac-address 00:11:22:33:44:55 — NetworkManager bond mac setting.
ifenslave bond0 eth1 eth2 — create bonding (older tool).
ip link add link eth0 name macvlan0 type macvlan mode bridge — create macvlan.
ip link add link eth0 name ipvlan0 type ipvlan mode l2 — create ipvlan L2.
ip link add macvlan0 link eth0 type macvlan mode private — macvlan private mode example.
ss -nltp | grep :6379 — check redis listening port.
netstat -s — protocol-level statistics.
ip -s maddress — multicast address stats.
ip maddr show — list multicast group memberships.
smcroute -g 0.0.0.0 eth0 — multicast route tools (if installed).
mrouted -v — multicast routing daemon (legacy).
pimd — PIM-D router daemon (if installed).
showmount -e host — NFS exports remote check.
mount -t nfs4 server:/export /mnt -o vers=4.2 — mount NFSv4.2.
nfsstat -s — NFS server stats.
exportfs -v — show local exports.
systemctl restart nfs-server — restart NFS service.
rpcinfo -p host — rpc endpoints list.
tcpdump -i eth0 -n 'udp and port 2049' — NFS traffic capture.
showmount -a — show mount clients (NFS).
mount -o remount,nfsvers=3 server:/export /mnt — force NFSv3.
nfsstat -c — NFS client stats.
dd if=/dev/zero of=/tmp/testfile bs=1M count=1024 conv=fsync — write test with fsync.
strace -f -e trace=file -o filetrace.txt program — trace file syscalls to file.
inotifywait -m /etc -e modify,create,delete — watch etc changes.
fanotify — kernel fs notification advanced (programmatic).
perf record -e syscalls:sys_enter_openat -a — trace openat syscalls system-wide.
perf trace -e open,openat -p <pid> — perf syscall trace per pid.
lsns -t net — list network namespaces.
ip netns pids ns1 — list pids in namespace.
nsenter --target <pid> --net -- bash — enter namespace of pid.
sshuttle -r user@host 0/0 — VPN-like transparently forward (python tool).
openconnect --protocol=anyconnect vpn.example.com — connect to Cisco AnyConnect compatible VPN.
vpnc — connect to classic vpnc (if configured).
strongswan statusall — strongSwan IKEv2 status.
ipsec statusall — strongswan status alias.
ipsec up conn-name — bring up specific connection.
ipsec down conn-name — bring down connection.
wg genkey | tee privatekey | wg pubkey > publickey — generate WireGuard keys.
wg-quick up wg0 — bring up WireGuard interface from config.
wg show — display WireGuard status.
ip xfrm state — show IPsec xfrm states.
ip xfrm policy — show xfrm policies.
setcap 'cap_net_bind_service=+ep' /usr/bin/program — allow binding low ports without root.
getcap /usr/bin/program — show capabilities.
capsh --print — show current capability set.
ss -tnp | awk '{print $5}' | cut -d: -f1 | sort | uniq -c — count connections per remote IP.
awk '{print $1}' /proc/net/snmp | paste - - — process snmp counters (advanced parsing).
grep -E 'segfault|core dumped' /var/log/messages — find crashes.
coredumpctl list — list systemd-coredumps.
coredumpctl gdb <PID> — open core in gdb via coredumpctl.
gdb -ex 'set pagination off' -ex 'thread apply all bt full' -batch -core core — batch backtrace.
rpm -qa --last | head — recently installed RPMs.
dpkg-query -W -f='${binary:Package} ${Version}\n' | sort — list Debian packages.
yum history info <id> — yum transaction info.
dnf history rollback <id> — rollback transaction (dnf).
apt-mark showmanual — list manually installed packages apt.
snap list — list snaps.
flatpak remotelist — flatpak remotes.
systemctl list-unit-files --state=enabled — enabled systemd units.
systemctl list-units --type=service --state=failed — failed services.
journalctl -u unit.service -b -1 — logs for unit from previous boot.
echo 1 > /proc/sys/kernel/sysrq — enable magic SysRq.
echo b > /proc/sysrq-trigger — reboot hard (no sync) (dangerous).
ip nht show — show non-hashed route cache (rare).
tc qdisc replace dev eth0 root cake — use CAKE qdisc (if kernel supports).
ss -tmi dst 10.0.0.1 — show TCP info metrics for dest.
iptables -I INPUT -p tcp --dport 22 -m recent --set --name SSH — setup recent module marker.
iptables -I INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 10 -j DROP — block brute force.
hostapd_cli -i wlan0 list_sta — list wifi stations connected.
iw dev wlan0 station dump — show per-station stats.
nlmon — netlink monitor interface (if supported).
ss -p -o state time-wait '( sport = :http or dport = :http )' — state and process info for time-wait.
systemd-run --unit=limittest -p CPUShares=50 sleep 60 — run with specific cgroup shares.
cgcreate -a user:user -g cpu,memory:groupname — create legacy cgroup v1 group.
cgexec -g cpu,memory:groupname stress --cpu 1 — run under cgroup.
xinetd — ancient super-server (legacy).
systemctl mask firewalld — prevent auto starting firewalld.
systemctl enable --now docker — enable and start docker service.
docker build --no-cache -t image:tag . — build image without cache.
docker system prune --all — cleanup docker unused images and containers.
docker image inspect --format='{{json .Config}}' image — show image config JSON.
podman ps -a --format json — podman container JSON list.
podman play kube pod.yaml — podman play kube manifest.
runc spec — generate OCI runtime spec template.
ctr images pull docker.io/library/alpine:latest — pull image via containerd ctr.
systemd-run --slice=machine.slice --unit=myvm --property=MemoryMax=2G qemu-system-x86_64 ... — start VM in cgroup slice (example).
virt-install --name vm --ram 2048 --vcpus 2 --disk size=20 --cdrom ubuntu.iso — create VM (libvirt).
virsh list --all — list VMs.
virsh domifaddr vm --source agent — get VM IP via guest agent.
brctl show — legacy bridge tool show (older kernels).
ip link set eth0 vf 0 mac 00:11:22:33:44:55 — set SR-IOV VF mac (if supported).
echo 1 > /sys/class/net/eth0/device/sriov_numvfs — enable SR-IOV VFs count.
tc filter show dev eth0 ingress — show ingress filters.
ethtool -c eth0 — show coalesce settings.
ethtool -C eth0 rx-usecs 50 — set coalescing.
iptables -A INPUT -i lo -j ACCEPT — accept loopback.
iptables -A OUTPUT -o lo -j ACCEPT — accept loopback outbound.
nft add table inet nat — create NAT table in nft.
nft add chain inet nat prerouting { type nat hook prerouting priority 0; } — nft nat prerouting chain.
nft add rule inet nat prerouting tcp dport 80 dnat to 10.0.0.5:8080 — nft DNAT.
nmcli device show eth0 | grep -i ip4 — show IP config via nmcli.
ip route show proto static — show static routes only.
ip route show table main — main table routes.
ip rule list | nl — list policy rules with numbers.
ip rule del pref 100 — delete rule by preference.
tc qdisc add dev eth0 root handle 1: prio bands 4 priomap 2 2 1 1 — prio qdisc example.
tc qdisc add dev eth0 root fq — fq qdisc for fairness.
tc qdisc add dev eth0 parent 1:1 handle 10: netem delay 10ms — combine netem class.
tc qdisc replace dev eth0 root fq_codel — replace qdisc.
ip maddr — multicast addresses again reminder.
multipath -ll — multipath device list.
dmsetup ls --tree — device mapper logical volumes tree.
udevadm control --reload — reload udev rules.
echo 1 > /proc/sys/kernel/printk — alter printk console loglevel (number differs semantics).
ss -o state connected — list connected sockets.
socat -d -d -x TCP-LISTEN:2222,reuseaddr,fork EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane — socat interactive shell via TCP (dangerous).
systemctl mask --now snapd — mask and stop unit.
ss -t -o state established '( sport = :http or dport = :http )' — established HTTP sockets (repeat for pattern).
ipvsadm -C — clear IPVS table.
ipset swap blacklist oldblacklist — swap ipsets atomically.
udevadm control --reload-rules && udevadm trigger — reload and retrigger udev.
rsyslogd -N1 — rsyslog config check.
nginx -g 'daemon off;' — run nginx in foreground for containers.
systemctl set-environment HTTP_PROXY='http://proxy:8080' — set service env var.
systemctl show-environment — see systemd environment variables.
systemctl set-property docker.service CPUQuota=50% — limit docker with systemd.
bmctl — (concept) BareMetal controller cli for special systems (example placeholder).
node -e "require('os').cpus().length" — Node.js get CPU count quick.
ss -lntu | wc -l — count listening sockets.
lsof -nP | egrep 'TCP|UDP' | wc -l — count open sockets via lsof.
cat /proc/net/snmp | sed -n '1,40p' — show SNMP kernel counters.
watch -n1 'cat /proc/net/udp | wc -l' — watch UDP socket count.
ss -H -nt | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head — top remote IPs by connection count.
echo 1 > /proc/sys/net/ipv4/conf/all/arp_ignore — change ARP behavior (advanced).
echo 2 > /proc/sys/net/ipv4/conf/all/arp_announce — reduce ARP announce.
ip route flush cache — flush routing cache (older kernels).
wg-quick down wg0 — bring down WireGuard interface.
wg set wg0 peer <key> persistent-keepalive 25 — set peer keepalive.
ip xfrm state flush — flush xfrm states.
ip xfrm policy flush — flush xfrm policies.
tcpdump -i eth0 -w - 'tcp and (tcp[13] & 8)!=0' | tcpreplay --intf1=eth1 - — capture and replay (pipe example).
tcpreplay --intf1=eth0 --pps=1000 large.pcap — replay captured traffic at pps.
virt-top — monitor virtual machines (like top).
virsh dommemstat vm — VM memory stats.
virsh domblklist vm — VM block device list.
virsh edit vm — edit VM XML (careful).
multipath -v2 — multipath verbose.
udevadm test-builtin persist /sys/class/net/eth0 — test builtin persist udev rule.
smartctl -H /dev/sda — quick SMART health.
hdparm -I /dev/sda | grep -i 'LB' — get logical block info (example).
cifscreds add //server/share — add cifs creds for mount (smbclient related tooling).
mount -t cifs //server/share /mnt -o username=user,vers=3.0 — mount CIFS share.
smbstatus — show SMB server status.
nmap --script smb-enum-shares.nse -p445 server — enumerate SMB shares.
tcpdump -i eth0 'tcp port 445' -w smb.pcap — capture SMB traffic.
iptables -t mangle -A POSTROUTING -p tcp -j CLASSIFY --set-class 1:1 — classify packets for tc.
tc filter add dev eth0 parent 1: protocol ip prio 1 handle 1 fw flowid 1:1 — filter by fwmark.
ip route add 10.0.0.0/24 dev eth1 scope link table 10 — route via device table link scope.
ip rule add to 10.0.0.0/24 table 10 pref 200 — policy rule by destination.
ip route show table local — local table for generated routes.
ss -tn src 10.0.0.1 — sockets with source.
iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 127.0.0.1:8080 — intercept local outbound to proxy.
socat TCP-LISTEN:8080,fork,reuseaddr TCP:upstream:80 — simple TCP proxy.
haproxy -m 16 — increase HAProxy mmap limit (example flag).
nginx -V — compiled options and modules.
ss -o state established '( sport = :https or dport = :https )' — established HTTPS sockets.
nmap -sV -sC --script=vuln host — service detection and vuln scripts (use carefully).
clamdscan -r /var/www — antivirus scan (if clamd installed).
auditctl -a always,exit -F arch=b64 -S connect -k netconnect — audit network connect syscalls.
ausearch -k netconnect -i — inspect audit connect events.
tcpdump -i eth0 -w /tmp/suspect.pcap 'tcp and (dst portrange 1-65535)' — capture suspicious traffic.
ss -R — show TCP retransmits summary.
cat /proc/net/netstat | sed -n '1,80p' — kernel netstat raw.
ip route show proto kernel — routes installed by kernel.
ip route replace 10.0.0.0/8 via 192.0.2.1 — atomic route replace.
nft add rule inet filter prerouting ip daddr 10.0.0.1 nat dnat to 192.168.1.2 — nft DNAT example.
ss -n state ESTABLISHED '( sport = :ssh or dport = :ssh )' — repeated patterns for quick checks.
tshark -i eth0 -f 'tcp port 22' -w ssh.pcap -c 1000 — capture limited number.
openssl ocsp -issuer issuer.pem -cert cert.pem -url http://ocsp.server — check OCSP.
curl --resolve example.com:443:10.0.0.5 https://example.com/ — test virtualhost resolution.
wget --no-check-certificate https://host/file — wget ignoring certs (careful).
ss -o state established '( sport = :imap or dport = :imap )' — IMAP connections.
cat /proc/sys/kernel/random/entropy_avail — available entropy.
rngd -r /dev/urandom — seed entropy (careful).
haveged — entropy daemon.
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target — prevent system suspend.
blkdiscard /dev/sda — discard (TRIM) entire device (use with caution).
fstrim -v / — discard unused blocks on filesystems supporting TRIM.
ls -l /sys/block/sda/queue/rotational — check if device is rotational.
hdparm --fibmap /path/file — show block mapping for file.
bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(arg1)); }' — trace openat with bpftrace.
bpftool net — show netlink-bpf attachments.
bpftool prog loadall prog_bpf.o /sys/fs/bpf/progdir — load BPF program objects.
cat /sys/kernel/debug/tracing/available_events | grep tcp — ftrace available events.
echo 1 > /sys/kernel/debug/tracing/events/tcp/tcp_probe/enable — enable tcp_probe tracepoint.
trace-cmd record -e sched_switch -e syscalls:sys_enter_openat -o trace.dat -- sleep 10 — record ftrace via trace-cmd.
trace-cmd report trace.dat — report ftrace results.
perf probe 'tcp_sendmsg' — create perf probe (if symbol available).
perf record -e probe:tcp_sendmsg -aR -- sleep 5 — perf on probe.
ss -o state established '( sport = :http or dport = :http )' — repeat useful ss filter.
iptables -N LOGDROP2 — create another chain for specialized logging.
tcpdump -i eth0 'tcp[13] & 2 != 0 and tcp[13] & 16 == 0' — SYN without ACK oddity.
nmap -Pn -sS -p22 --script ssh2-enum-algos host — enumerate SSH algorithms.
openssl s_client -connect host:5222 -starttls xmpp — XMPP STARTTLS test.
openssl s_client -connect host:993 -crlf — IMAPS test.
python -m smtpd -n -c DebuggingServer localhost:1025 — local SMTP debug server.
ss -s && free -h && df -h — combined quick health checks.
systemctl list-jobs — look at queued systemd jobs.
systemctl show -p FragmentPath unit — show unit file path.
systemctl cat unit — show full unit contents.
journalctl --output=cat -u unit — raw logs for unit.
journalctl --disk-usage — journal size.
journalctl --rotate && journalctl --vacuum-time=2weeks — rotate and vacuum.
sestatus -v — verbose SELinux status.
ausearch -m AVCS -i — SELinux access denials.
isolate -d --run ./test — isolate process using cgroup-based isolation (tool example).
bpftrace -e 'kprobe:vfs_write /comm=="nginx"/ { @[comm] = count(); }' — bpf trace vfs_write counts.
socat - /dev/ttyUSB0,rawer — connect serial over stdio.
screen /dev/ttyUSB0 115200 — access serial console.
setserial -g /dev/ttyS* — list serial ports config.
ntfs-3g /dev/sdb1 /mnt/ntfs — mount NTFS rw (userland).
mount -o loop,offset=$((512*2048)) disk.img /mnt — mount partition inside image (offset in bytes).
partx -a /dev/loop0 — re-read partition table for loop.
losetup -d /dev/loop0 — detach loop device.
dmsetup ls — list device-mapper devices.
lvcreate -L1G -s -n snapshot vgdata/lvdata — create LV snapshot.
lvremove /dev/vgdata/snapshot — remove LV snapshot.
lsof /path|wc -l — count open files on path.
ss -tan state FIN-WAIT-1 — show FIN-WAIT-1 sockets.
ss -tan state SYN-RECV — show SYN-RECV sockets (backlog issues).
awk '{sum+=$2}END{print sum}' /proc/net/snmp — sum specific SNMP counters (example usage).
python -c "import socket; s=socket.socket(); s.bind(('0.0.0.0',0)); print(s.getsockname())" — quick ephemeral port bind.
nmap --script http-slowloris --max-parallelism 2 target — test slowloris (use on allowed infra).
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j CONNMARK --set-mark 1 — mark for connmark usage.
connmark -L — (concept) list connmarks (tool specifics vary).
tc filter add dev eth0 protocol ip parent 1: prio 1 handle 1 fw flowid 1:1 — tc filter fwmatch example.
ip -s -s link show dev bond0 — show bond stats double-s sample.
journalctl -u docker.service --since "2 hours ago" — docker logs last 2 hours.
docker logs --tail 200 -f container — follow last logs.
docker stats --no-stream — snapshot container stats.
docker exec -it container ss -tulpn — check inside container listeners.
docker network create --driver bridge --subnet 172.20.0.0/16 mynet — create docker network custom.
docker run --network mynet --ip 172.20.0.10 ... — start container on custom network IP.
podman network create mynet — create podman network.
podman run --network mynet --ip 10.88.0.10 — podman run with static ip.
crontab -l -u root — list root cronjobs.
anacron -S — start anacron job scheduling (system specifics).
logrotate -d /etc/logrotate.conf — debug logrotate config.
logrotate -f /etc/logrotate.d/myconf — force rotate.
rsync --bwlimit=5000 -a src dst — rsync with bandwidth limit.
iptables -t raw -I PREROUTING -p tcp --dport 22 -j TRACE — enable trace logging chain (experimental).
ip monitor route — watch route changes.
ip monitor neigh — watch neighbor updates.
ip monitor all — watch all network changes (repeat reminder).
ss --ipv6 -lntu — list IPv6 listening sockets.
curl -sS --unix-socket /var/run/docker.sock http://v1.24/containers/json — talk to docker API via unix socket.
socat - UNIX-CONNECT:/var/run/docker.sock — raw socket debugging.
docker network inspect bridge --format '{{json .Containers}}' — see containers in default bridge.
docker rm -f $(docker ps -aq) — force remove all containers (dangerous).
docker volume prune -f — remove unused volumes.
iptables -t nat -L PREROUTING -n -v — show nat prerouting counters.
watch -n0.5 'cat /proc/net/netstat | sed -n "1,40p"' — high-frequency watch kernel stats (careful).
sed -n '1,200p' /var/log/kern.log — show kernel log head.
grep -R --exclude-dir={.git,node_modules} -n 'TODO' /srv — search codebase for TODOs.
git fsck --full — verify git repo integrity.
git reflog expire --expire=now --all && git gc --prune=now --aggressive — prune git repo aggressively.
systemd-run --unit=mytask -p CPUWeight=10 nohup ./task & — run with CPU weight.
strace -e trace=%file -ff -o /tmp/strace_prog ./prog — file syscall tracing to files.
gdb -batch -ex 'thread apply all bt' -ex 'quit' -p <pid> > /tmp/backtraces.txt — batch backtrace.
ss -o state established sport = :80 or dport = :80 — show established HTTP sockets succinctly.
nc -l -p 3389 > /tmp/rdesktop_dump — capture rdesktop traffic (example).
openssl s_client -connect host:443 -cipher 'ECDHE-RSA-AES256-GCM-SHA384' — force cipher test.
ngrep -d eth0 -W byline 'POST ' tcp and port 80 — pattern match POST requests.
ss -i dst 10.0.0.1 dport = :80 — show in-depth TCP info for connection.
ip route add 10.10.0.0/16 dev vxlan0 proto kernel scope link src 10.1.1.1 — add vxlan route example.
bridge fdb append 00:aa:bb:cc:dd:ee dev vtep0 dst 192.168.0.2 — add FDB with VTEP destination.
ip -d link show vxlan0 — show vxlan device details.
ip link add vxlan0 type vxlan id 100 local 10.1.1.1 dstport 4789 dev eth0 — create vxlan device.
bridge link show — display bridge ports (repeat helpful).
ip link set vxlan0 up — bring vxlan up.
bridge vlan add vid 100 dev vxlan0 — map vlan to vxlan.
iptables -t mangle -A PREROUTING -p udp --dport 4789 -j DSCP --set-dscp 46 — mark vxlan control for QoS.
tcpdump -i eth0 udp port 4789 -w vxlan.pcap — capture vxlan encaps packets.
ovs-vsctl add-br br0 — create OVS bridge.
ovs-vsctl add-port br0 veth0 — add port to OVS bridge
