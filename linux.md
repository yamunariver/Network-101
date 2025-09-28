

This tier handles **high-performance routing, storage management, virtualization, and system-wide monitoring**.

### **Networking**

| Command                                                         | Description                             |
| --------------------------------------------------------------- | --------------------------------------- |
| `ip route show`                                                 | View routing table.                     |
| `ip route add <net>/<mask> via <next-hop>`                      | Add static route.                       |
| `ip link add bond0 type bond`                                   | Create bonded interface for redundancy. |
| `cat /proc/sys/net/ipv4/ip_forward`                             | Check if IPv4 forwarding is enabled.    |
| `sysctl -w net.ipv4.ip_forward=1`                               | Enable routing.                         |
| `tc qdisc show dev eth0`                                        | Check QoS/traffic shaping.              |
| `ethtool -S eth0`                                               | NIC statistics (errors, drops).         |
| `vxlan add vxlan100 id 100 dev eth0 remote <peer> dstport 4789` | Create VXLAN overlay.                   |
| `ip link set vxlan100 up`                                       | Activate VXLAN.                         |

### **Storage**

| Command                                                                                   | Description                              |
| ----------------------------------------------------------------------------------------- | ---------------------------------------- |
| `lsblk`                                                                                   | Show block devices and partitions.       |
| `blkid`                                                                                   | Show filesystem UUIDs.                   |
| `mount /dev/sdb1 /mnt/data`                                                               | Mount storage volume.                    |
| `umount /mnt/data`                                                                        | Unmount filesystem.                      |
| `mdadm --create --verbose /dev/md0 --level=5 --raid-devices=3 /dev/sdb /dev/sdc /dev/sdd` | Create RAID 5 array.                     |
| `lvs`, `vgs`, `pvs`                                                                       | Show LVM logical/volume/physical groups. |
| `lvcreate -L 50G -n lv_data vg1`                                                          | Create LVM logical volume.               |
| `mkfs.ext4 /dev/vg1/lv_data`                                                              | Format LV with ext4.                     |
| `btrfs subvolume create /mnt/btrfs/data`                                                  | Create Btrfs subvolume.                  |
| `zpool create pool1 mirror /dev/sdb /dev/sdc`                                             | Create ZFS mirror pool.                  |

### **System & Performance**

| Command                                                                 | Description                     |
| ----------------------------------------------------------------------- | ------------------------------- |
| `htop`                                                                  | Interactive process monitoring. |
| `perf top`                                                              | CPU profiling.                  |
| `bpftrace -e 'tracepoint:syscalls:sys_enter_* { @[probe] = count(); }'` | Kernel syscall tracing.         |
| `numactl --hardware`                                                    | Show NUMA topology.             |
| `sysctl -a`                                                             | List kernel parameters.         |
| `dmesg -T`                                                              | Kernel logs with timestamps.    |

---

## **2️⃣ Distribution Tier (Aggregation / Policy / Security / Storage Access)**

This tier manages **access control, traffic shaping, policy enforcement, shared storage access, and VLAN aggregation**.

### **Networking**

| Command                                                                                     | Description                          |
| ------------------------------------------------------------------------------------------- | ------------------------------------ |
| `ip link show`                                                                              | List interfaces.                     |
| `ip addr add 192.168.10.1/24 dev eth1`                                                      | Assign VLAN interface IP.            |
| `iptables -A FORWARD -i eth1 -o eth2 -j ACCEPT`                                             | Allow traffic forwarding.            |
| `nft list ruleset`                                                                          | Inspect modern firewall rules.       |
| `ip link add name br10 type bridge`                                                         | Create Layer2 bridge.                |
| `ip link set eth1 master br10`                                                              | Add interface to bridge.             |
| `tc class add dev eth1 parent 1: classid 1:10 htb rate 100mbit`                             | QoS shaping.                         |
| `ip vrf add RED`                                                                            | Create VRF for network segmentation. |
| `ip link set dev eth1 vrf RED`                                                              | Assign interface to VRF.             |
| `ovs-vsctl add-br br0`                                                                      | Create Open vSwitch bridge.          |
| `ovs-vsctl add-port br0 vxlan0 -- set interface vxlan0 type=vxlan options:remote_ip=<peer>` | VXLAN overlay.                       |

### **Storage / File Services**

| Command                                              | Description                        |
| ---------------------------------------------------- | ---------------------------------- |
| `showmount -e`                                       | Check NFS exports.                 |
| `mount -t nfs server:/export /mnt/nfs`               | Mount NFS share.                   |
| `df -h`                                              | Show disk usage.                   |
| `du -sh /mnt/data/*`                                 | Check folder sizes.                |
| `rsync -av --progress /data/backup/ server:/backup/` | Efficient replication.             |
| `iscsiadm -m discovery -t st -p <target-ip>`         | Discover iSCSI targets.            |
| `systemctl start nfs-server`                         | Start NFS server for distribution. |

### **System / Monitoring**

| Command                          | Description                             |                                 |
| -------------------------------- | --------------------------------------- | ------------------------------- |
| `journalctl -u nfs-server`       | Monitor NFS logs.                       |                                 |
| `lsof                            | grep nfs`                               | Check open files on NFS mounts. |
| `tcpdump -i br10 vlan 10`        | Capture traffic on VLAN bridge.         |                                 |
| `iperf3 -s` / `iperf3 -c <host>` | Test link throughput.                   |                                 |
| `smartctl -a /dev/sdb`           | Check disk health (S.M.A.R.T).          |                                 |
| `dmidecode`                      | View hardware info (memory, CPU, etc.). |                                 |

---

## **3️⃣ Access Tier (Edge / End Users / Desktops / Small Servers)**

Handles **end-user connectivity, DHCP, security, local storage, and basic monitoring**.

### **Networking**

| Command                                       | Description                             |
| --------------------------------------------- | --------------------------------------- |
| `ip link set eth0 up`                         | Enable access interface.                |
| `ip addr add 192.168.20.10/24 dev eth0`       | Assign IP.                              |
| `dhclient eth0`                               | Get DHCP lease.                         |
| `ip neigh show`                               | Show ARP table.                         |
| `arp -d <ip>`                                 | Delete stale ARP entries.               |
| `ping 192.168.10.1`                           | Test connectivity to distribution tier. |
| `traceroute 8.8.8.8`                          | Trace path to external network.         |
| `bonding mode=802.3ad miimon=100 updelay=200` | Redundant uplinks for critical hosts.   |

### **Storage / Filesystem**

| Command                                 | Description            |
| --------------------------------------- | ---------------------- |
| `lsblk`                                 | List attached storage. |
| `mount /dev/sdb1 /mnt/data`             | Mount storage.         |
| `umount /mnt/data`                      | Unmount storage.       |
| `df -h`                                 | Disk usage.            |
| `du -sh /home/user/*`                   | Folder sizes.          |
| `rsync -av /home/user/ server:/backup/` | Backup user data.      |

### **System / Troubleshooting**

| Command           | Description                               |
| ----------------- | ----------------------------------------- |
| `top` / `htop`    | CPU & memory usage.                       |
| `free -h`         | Memory status.                            |
| `vmstat 1`        | System performance stats.                 |
| `iostat -x 1`     | Disk I/O performance.                     |
| `ss -tunlp`       | Active TCP/UDP connections and processes. |
| `journalctl -xe`  | Recent system logs.                       |
| `strace -p <pid>` | Trace syscalls of process.                |
| `lsof -i :80`     | Check which process uses port 80.         |

---


