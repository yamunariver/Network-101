

## 1. Basic / System / Global Configuration

1. `enable` – go to privileged EXEC
2. `disable` – return to user EXEC
3. `configure terminal` – enter global config mode
4. `hostname NAME` – set device hostname
5. `no hostname` – remove configured hostname
6. `banner motd #MESSAGE#` – set a message-of-day banner
7. `service password-encryption` – encrypt plain-text passwords in config
8. `enable secret <password>` – set encrypted enable password
9. `enable password <password>` – set plain-text enable password
10. `clock set HH:MM:SS MONTH DAY YEAR` – manually set system time
11. `show clock` – display current clock
12. `reload` – reboot device
13. `copy running-config startup-config` – save running config
14. `write memory` – alternate save command
15. `copy startup-config running-config` – merge saved config into running
16. `erase startup-config` – delete startup config
17. `show version` – show version, uptime, hardware, etc.
18. `show running-config` – display active configuration
19. `show startup-config` – display saved configuration
20. `show inventory` – display hardware inventory
21. `no ip domain-lookup` – disable DNS name lookups (prevents delay)
22. `ip domain-name example.com` – set domain name (needed for crypto / SSH)
23. `alias exec reload do reload` – alias commands
24. `terminal length 0` – show all output without pausing
25. `terminal history size 200` – set command history size
26. `archive` / `archive config` – enable config archive features
27. `boot system flash:<image.bin>` – set IOS image to boot
28. `show boot` – show boot info
29. `verify /md5 flash:<image.bin>` – verify image checksum
30. `license install flash:<license.lic>` – install license
31. `license clear` – remove license
32. `show platform` – show platform-specific hardware info
33. `show environment` – show temperature, fan, PSU status
34. `show diag` – diagnostics information
35. `show processes cpu` – CPU usage
36. `show processes memory` – memory usage
37. `show logging` – view system logs
38. `logging buffered 10000` – set log buffer size
39. `logging host <ip>` – send logs to syslog server
40. `terminal monitor` – display logs on your terminal
41. `show line` – show line (console/VTY) stats
42. `exec-timeout 10` – set timeout (minutes) for line
43. `no exec-timeout` – disable timeout
44. `logging synchronous` – avoid log output interrupting prompt

---

## 2. User / AAA / Security / ISE / 802.1X (dot1x)

45. `username admin privilege 15 secret <pwd>` – create local privileged user
46. `no username admin` – remove a user
47. `aaa new-model` – enable AAA
48. `aaa authentication login default local` – default login method
49. `aaa authorization exec default local` – exec authorization
50. `aaa authentication dot1x default group radius` – 802.1x authentication via RADIUS
51. `aaa authorization network default group radius` – network (post-auth) authorization
52. `aaa accounting dot1x default start-stop group radius` – accounting for dot1x
53. `aaa accounting update newinfo periodic <mins>` – periodic accounting updates
54. `radius-server host <ip> auth-port 1812 acct-port 1813 key <secret>` – define RADIUS server
55. `radius-server retransmit 3` – retries
56. `radius-server timeout 5` – timeout
57. `ip radius source-interface Loopback0` – use specific source interface for RADIUS
58. `dot1x system-auth-control` – enable 802.1x globally
59. `aaa server radius dynamic-author` – dynamic authorization (Change of Authorization)
60. `radius server <name>` … (address, timeouts, etc.) – define named RADIUS server
61. `radius-server dead-criteria time <sec> tries <n>` – RADIUS server fail criteria
62. `radius-server attribute 31 mac format ietf upper-case` – include MAC in requests
63. `class-map type control subscriber match-all DOT1X_NO_AGENT` – (for ISE / CTS) match condition
64. `match method dot1x` – match authentication method
65. `match result-type agent-not-found` – match result type
66. `cts role-based enforcement` – enable Cisco TrustSec role-based enforcement
67. `cts manual` – manual SGT (Security Group Tag) assignment
68. `cts credentials id <id> password <pw>` – set CTS credentials
69. `cts server <ip>` – specify ISE for CTS
70. `show cts role-based policy` – view CTS policy
71. `show cts environment-data` – view environment data

---

## 3. Interface / Port Configuration (Access, Trunk, Security, PoE, QoS, Voice)

Enter interface mode (e.g. `interface GigabitEthernet1/0/1`) or interface range (`interface range g1/0/1-48`).

### Basic Interface

72. `description <text>` – description of port purpose
73. `switchport` – enable L2 switchport mode
74. `no switchport` – convert to routed port (L3)
75. `switchport mode access` – force access mode
76. `switchport access vlan <vlan-id>` – assign access VLAN
77. `switchport mode trunk` – set trunk mode
78. `switchport trunk encapsulation dot1q` – 802.1Q encapsulation (if supported)
79. `switchport trunk native vlan <vlan-id>` – native VLAN
80. `switchport trunk allowed vlan <list>` – allow VLANs on trunk
81. `speed auto` / `speed <value>` – set or auto-negotiate speed
82. `duplex auto` / `duplex full` – duplex setting
83. `mtu <size>` – set MTU
84. `spanning-tree portfast` – immediate forwarding (for access ports)
85. `spanning-tree bpduguard enable` – protect against BPDUs

### Port Security

86. `switchport port-security` – enable port-security
87. `switchport port-security maximum <number>` – max MAC count
88. `switchport port-security mac-address sticky` – learn and save MACs dynamically
89. `switchport port-security mac-address <MAC>` – manually set allowed MAC
90. `switchport port-security violation shutdown` – shutdown on violation
91. `switchport port-security violation restrict` – restrict (drop violation)
92. `switchport port-security violation protect` – silently drop unknowns
93. `show port-security` – show global port-security status
94. `show port-security interface <int>` – details per port
95. `clear port-security sticky interface <int>` – clear learned sticky entries

### PoE (Power over Ethernet)

96. `power inline auto` – enable PoE auto detection
97. `power inline never` – disable PoE
98. `power inline static` – static delivery
99. `power inline police` – enforce power limit
100. `show power inline` – show PoE status global
101. `show power inline <int>` – show per-port PoE

### Voice / IP Phone / QoS

102. `switchport voice vlan <vlan-id>` – designate voice VLAN
103. `mls qos trust cos` – trust CoS from attached phone
104. `auto qos voip cisco-phone` – auto QoS for Cisco phones
105. `auto qos voip trust` – trust DSCP/CoS marks
106. `mls qos` – enable QoS globally
107. `mls qos trust dscp` – trust DSCP from end devices
108. `priority-queue out` – priority egress queue
109. `srr-queue bandwidth share 10 10 60 20` – share bandwidth across queues
110. `storm-control broadcast level 1.00 0.90` – broadcast storm control
111. `storm-control multicast level 0.50 0.40` – multicast storm control
112. `storm-control unicast level 0.50 0.40` – unknown unicast storm control
113. `show storm-control` – show storm control status

### EtherChannel / Link Aggregation

114. `channel-group 1 mode active` – LACP active
115. `channel-group 1 mode passive` – LACP passive
116. `channel-group 1 mode on` – static channel (no protocol)
117. `show etherchannel summary` – overview of EtherChannels
118. `show lacp neighbor` – LACP neighbor info

### Monitoring / Diagnostics per Port

119. `show interfaces <int>` – detailed status & stats
120. `show controllers ethernet-controller <int>` – hardware-level diagnostics (platform-specific)
121. `test cable-diagnostics tdr interface <int>` – run TDR cable test
122. `show cable-diagnostics tdr interface <int>` – show TDR results
123. `mac address-table static <MAC> vlan <vlan> interface <int>` – static MAC entry
124. `no mac address-table static <MAC> vlan <vlan>` – remove static MAC
125. `service-policy input <policy>` – apply input QoS policy
126. `service-policy output <policy>` – apply output QoS policy

---

## 4. VLAN / Switching / Stacking / STP / Switching Features

127. `vlan <id>` – create or enter VLAN config
128. `name <VLAN_NAME>` – name VLAN
129. `no vlan <id>` – remove VLAN
130. `exit` – leave VLAN config
131. `interface vlan <vlan-id>` – SVI / switched virtual interface
132. `ip address <ip> <mask>` – assign IP to SVI
133. `no ip address` – remove SVI IP
134. `show vlan brief` – VLAN summary
135. `show interfaces trunk` – trunk port info
136. `spanning-tree mode rapid-pvst` – use Rapid PVST+
137. `spanning-tree vlan <id> root primary` – set primary root bridge
138. `show spanning-tree` – STP status
139. `show mac address-table` – MAC table
140. `clear mac address-table dynamic` – clear dynamic entries

### Stacking (StackWise / Stack)

141. `show switch` – show stack members and roles
142. `show switch stack-ports` – stack port status
143. `show switch neighbors` – stacking neighbor discovery
144. `switch stack-member-number priority <value>` – set priority
145. `switch stack-member-number renumber <new-number>` – renumber member
146. `switch stack-member-number provision <model>` – pre-provision before adding
147. `reload slot <member-number>` – reload a specific member
148. `stack-mac persistent timer 0` – persistent stack MAC
149. `show platform stack-manager all` – deep stack diagnostics

---

## 5. Routing / IP / ACL / NAT / Static & Dynamic Routing

150. `ip routing` – enable IPv4 routing
151. `ip route 0.0.0.0 0.0.0.0 <next-hop>` – default route
152. `ip route <net> <mask> <next-hop>` – static route
153. `show ip route` – routing table
154. `show ip protocols` – dynamic routing protocol status
155. `router ospf <process>` – start OSPF
156. `network <net> <wildcard> area <area-id>` – OSPF network
157. `router eigrp <asn>` – start EIGRP
158. `network <net>` – advertise in EIGRP
159. `router bgp <asn>` – start BGP
160. `neighbor <ip> remote-as <asn>` – BGP neighbor
161. `show ip bgp summary` – BGP summary
162. `show ip ospf neighbor` – OSPF neighbor view
163. `show ip eigrp neighbors` – EIGRP neighbor view
164. `access-list <num> permit <net> <wildcard>` – ACL rule
165. `access-list <num> deny any` – deny all remaining
166. `ip access-group <num> in` / `out` – apply ACL inbound/outbound
167. `ip nat inside` / `ip nat outside` – tag NAT inside/outside interface
168. `ip nat inside source list <acl> interface <int> overload` – NAT overload (PAT)
169. `show access-lists` – view ACLs
170. `show ip nat translations` – see NAT table
171. `clear ip nat translation *` – clear NAT table

---

## 6. VPN / Crypto / IPSec / ISAKMP / IKE

172. `crypto isakmp policy 10` – define ISAKMP policy
173. `encryption aes 256` – set encryption algorithm
174. `hash sha` – set hash method
175. `authentication pre-share` – pre-shared key authentication
176. `group 2` – DH group
177. `crypto isakmp key <key> address <peer-ip>` – shared-key with peer
178. `crypto ipsec transform-set TS esp-aes esp-sha-hmac` – transform set
179. `crypto map VPNMAP 10 ipsec-isakmp` – create crypto map
180. `set peer <ip>` – set peer IP
181. `match address <acl>` – define traffic ACL
182. `interface <int>` → `crypto map VPNMAP` – attach crypto map
183. `show crypto isakmp sa` – show ISAKMP Security Associations
184. `show crypto ipsec sa` – show IPSec SAs

---

## 7. Monitoring / Troubleshooting / Diagnostics

185. `ping <dest>` – test IPv4 connectivity
186. `ping ipv6 <dest>` – test IPv6 connectivity
187. `traceroute <dest>` – trace path
188. `show cdp neighbors` – Cisco discovery
189. `show lldp neighbors` – LLDP discovery
190. `show arp` – display ARP table
191. `clear arp` – clear ARP entries
192. `debug ip packet` – debug IP packets
193. `undebug all` / `no debug all` – turn off debugging
194. `show processes` – process list
195. `show tech-support` – full diagnostic dump
196. `dir flash:` – list flash contents
197. `delete flash:<filename>` – delete file
198. `copy tftp flash:` / `copy flash: tftp:` – transfer images
199. `verify /md5 flash:<image>` – verify checksum
200. `show ip sla statistics` – IP SLA results
201. `ip sla <id>` → `icmp-echo <dest>` → `frequency <sec>` → `ip sla schedule <id> life forever start-time now` – configure SLA test
202. `track <id> ip sla <id> reachability` – track SLA result
203. `show track` – show tracked objects

---

## 8. VXLAN / Overlay / Underlay / EVPN

Below is a representative set of commands for VXLAN configuration (underlay + overlay), EVPN, VNI, etc. These apply mostly on IOS-XE / LISP-VXLAN capable platforms or similar. Use only on devices that support it. (Based partially on Cisco docs) ([Cisco][1])

204. `feature nv overlay` – enable overlay (VXLAN) features
205. `feature vn-segment-vlan-based` – enable VLAN-to-VNI mapping
206. `feature interface-vlan` – enable SVI support
207. `interface nve1` – NVE (Network Virtualization Edge) interface
208. `no shutdown` – bring NVE up
209. `source-interface loopback0` – set NVE source interface for VTEP
210. `host-reachability protocol bgp` – use BGP EVPN for host reachability
211. `member vni <vni-id> associate-vrf <vrf-name>` – map VNI to VRF
212. `member vni <vni-id> mcast-group <mcast-ip>` – set multicast group for flooding
213. `member vni <vni-id> ingress-replication protocol bgp` – ingress replication
214. `vrf <vrf-name>` – enter VRF config
215. `rd <asn>:<num>` – route distinguisher
216. `route-target import <asn>:<num>` / `route-target export <asn>:<num>` – RT config
217. `router bgp <asn>` – BGP instance for EVPN
218. `address-family l2vpn evpn` – EVPN address family
219. `neighbor <peer-ip> activate` – activate neighbor in EVPN family
220. `advertise-all-vni` – advertise all mapped VNIs
221. `show nve interface` – show NVE status
222. `show nve vni` – show VNI mappings
223. `show nve peers` – show peer VTEPs
224. `show bgp l2vpn evpn` – BGP EVPN status
225. `show bgp l2vpn evpn <vni>` – EVPN info for that VNI
226. `show ip route vrf <vrf> <network>` – show route in VRF
227. `show ip bgp vrf <vrf> l2vpn evpn` – VRF-specific EVPN
228. `interface Vlan <vlan-id>` → `vn-segment <vni-id>` – map VLAN to VNI
229. `ip route vrf <vrf> <net> <mask> <next-hop>` – static route in VRF underlay
230. `show ip route vrf <vrf>` – routes within VRF
231. `show ip bgp summary` – BGP summary including EVPN
232. `clear bgp <asn> l2vpn evpn` – clear EVPN BGP sessions
233. `show mpls ldp neighbor` – if MPLS underlay used
234. `show ip mroute vrf <vrf>` – multicast underlay routes
235. `ip igmp snooping vxlan` – enable IGMP snooping for VXLAN VLANs ([Cisco Press][2])
236. `show ip igmp snooping vxlan` – view IGMP snooping for VXLAN
237. `show device-tracking database` – track endpoint devices (MAC, IP) under VXLAN / overlay operations ([Cisco][3])

---

## Example Combined Config Snippets

### Example: Underlay + Overlay + VLAN-to-VNI

```text
configure terminal
 ! Underlay: enable features
 feature nv overlay
 feature vn-segment-vlan-based
 feature interface-vlan

 ! Configure loopback used as VTEP source
 interface Loopback0
  ip address 10.1.1.1/32
 exit

 ! SVIs or VLANs
 interface Vlan 10
  ip address 192.168.10.1 255.255.255.0
  vn-segment 10010
 exit

 interface Vlan 20
  ip address 192.168.20.1 255.255.255.0
  vn-segment 10020
 exit

 ! NVE interface
 interface nve1
  no shutdown
  source-interface loopback0
  host-reachability protocol bgp
  member vni 10010 associate-vrf default
  member vni 10010 ingress-replication protocol bgp
  member vni 10020 associate-vrf default
  member vni 10020 ingress-replication protocol bgp
 exit

 ! BGP EVPN for overlay control plane
 router bgp 65001
  bgp log-neighbor-changes
  address-family l2vpn evpn
   neighbor 10.2.2.2 activate
   advertise-all-vni
  exit-address-family
 exit

 ! Underlay static or dynamic routing (e.g. OSPF / static)
 ip route 10.2.2.0 255.255.255.0 10.1.2.2
```

### Example: Port with dot1x + VLAN-to-VNI mapping

```text
interface GigabitEthernet1/0/5
 description Host port – 802.1x
 switchport mode access
 switchport access vlan 10
 authentication order dot1x mab
 authentication priority dot1x mab
 authentication port-control auto
 mab
 dot1x pae authenticator
 spanning-tree portfast
 spanning-tree bpduguard enable
```


