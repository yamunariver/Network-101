# Network-101



##  **Basic Device & System Commands**

1. enable
2. disable
3. exit
4. logout
5. reload
6. clock set HH:MM:SS MONTH DAY YEAR
7. show version
8. show running-config
9. show startup-config
10. write memory
11. copy running-config startup-config
12. copy startup-config running-config
13. erase startup-config
14. delete flash:<filename>
15. show history
16. terminal history size 200
17. show processes cpu
18. show processes memory
19. show environment
20. show inventory

---

## 2️⃣ **User & Privilege Mode**

21. configure terminal
22. hostname <name>
23. enable secret <password>
24. enable password <password>
25. service password-encryption
26. username <user> privilege 15 secret <pass>
27. no service password-encryption
28. banner motd #Authorized access only#

---

## 3️⃣ **Interface Configuration**

29. interface GigabitEthernet0/0
30. interface FastEthernet0/1
31. interface range Gi1/0/1-48
32. description Uplink-to-Core
33. ip address 192.168.1.1 255.255.255.0
34. no ip address
35. shutdown
36. no shutdown
37. speed 1000
38. duplex full
39. negotiation auto
40. switchport
41. switchport mode access
42. switchport mode trunk
43. switchport trunk allowed vlan 10,20
44. switchport trunk encapsulation dot1q
45. switchport access vlan 20
46. spanning-tree portfast
47. spanning-tree bpduguard enable
48. storm-control broadcast level 50
49. channel-group 1 mode active
50. no cdp enable

---

## 4️⃣ **VLAN Configuration**

51. vlan 10
52. name HR
53. vlan 20
54. name Finance
55. show vlan brief
56. delete vlan.dat
57. interface vlan 1
58. ip address 10.0.0.1 255.255.255.0
59. no shutdown

---

## 5️⃣ **Routing (Static & Dynamic)**

60. ip route 0.0.0.0 0.0.0.0 192.168.1.254
61. ip route 10.10.10.0 255.255.255.0 192.168.1.2
62. router ospf 1
63. network 10.0.0.0 0.255.255.255 area 0
64. passive-interface default
65. no passive-interface Gi0/0
66. show ip ospf neighbor
67. router eigrp 100
68. network 192.168.0.0 0.0.255.255
69. router bgp 65001
70. neighbor 10.0.0.2 remote-as 65002
71. show ip bgp summary
72. show ip route
73. show ip protocols
74. no router ospf 1

---

## 6️⃣ **Connectivity & Testing**

75. ping 8.8.8.8
76. ping 192.168.1.1 source vlan1
77. traceroute 8.8.8.8
78. telnet 192.168.1.1
79. ssh -l admin 192.168.1.1
80. show cdp neighbors
81. show lldp neighbors
82. show arp
83. show ip arp
84. show mac address-table
85. clear arp-cache
86. show ip interface brief
87. show interface status
88. show interfaces counters errors
89. show interfaces description
90. show etherchannel summary

---

## 7️⃣ **Access Control & Security**

91. access-list 10 permit 192.168.1.0 0.0.0.255
92. access-list 10 deny any
93. ip access-group 10 in
94. ip access-group 10 out
95. line vty 0 4
96. password cisco
97. login local
98. transport input ssh
99. transport input telnet ssh
100. crypto key generate rsa modulus 2048
101. ip ssh version 2
102. ip domain-name mynet.local
103. login block-for 60 attempts 3 within 30
104. exec-timeout 10 0
105. service tcp-keepalives-in
106. service tcp-keepalives-out

---

## 8️⃣ **NAT / PAT**

107. ip nat inside source static 192.168.1.10 203.0.113.10
108. ip nat inside source list 1 interface Gig0/0 overload
109. access-list 1 permit 192.168.1.0 0.0.0.255
110. interface Gig0/0
111. ip nat outside
112. interface Gig0/1
113. ip nat inside
114. show ip nat translations
115. clear ip nat translation *

---

## 9️⃣ **DHCP**

116. ip dhcp pool LAN
117. network 192.168.1.0 255.255.255.0
118. default-router 192.168.1.1
119. dns-server 8.8.8.8
120. lease 7
121. ip dhcp excluded-address 192.168.1.1 192.168.1.10
122. show ip dhcp binding
123. show ip dhcp pool

---

## 🔟 **Spanning Tree**

124. spanning-tree mode rapid-pvst
125. spanning-tree vlan 1 root primary
126. spanning-tree vlan 1 root secondary
127. spanning-tree guard loop
128. show spanning-tree
129. show spanning-tree root

---

## 11️⃣ **QoS & Traffic Control**

130. mls qos
131. policy-map SHAPE
132. class-map VOICE
133. match ip dscp ef
134. priority 128
135. service-policy input SHAPE
136. show policy-map interface

---

## 12️⃣ **Monitoring & Logging**

137. logging buffered 16384
138. logging console
139. logging trap warnings
140. logging host 192.168.1.100
141. show logging
142. debug ip packet
143. no debug all
144. show tech-support
145. archive config
146. archive
147. path flash:/archive
148. maximum 14

---

## 13️⃣ **SNMP & Syslog**

149. snmp-server community public RO
150. snmp-server community private RW
151. snmp-server location DataCenter
152. snmp-server contact Admin
153. snmp-server enable traps
154. show snmp

---

## 14️⃣ **Advanced Switching**

155. show interface trunk
156. vtp mode transparent
157. vtp domain MYDOMAIN
158. vtp password mypass
159. show vtp status
160. show power inline
161. macro apply cisco-desktop
162. show errdisable recovery
163. errdisable recovery cause bpduguard

---

## 15️⃣ **High Availability**

164. redundancy
165. mode sso
166. show redundancy
167. standby 1 ip 10.0.0.2
168. standby 1 priority 110
169. standby 1 preempt
170. show standby brief

---

## 16️⃣ **Stack & EtherChannel**

171. show switch
172. switch stack-member-number priority 15
173. switch stack-member-number renumber 2
174. stack port enable
175. interface port-channel1
176. show etherchannel load-balance

---

## 17️⃣ **Wireless (for WLC/Capable IOS)**

177. dot11 ssid OFFICE
178. authentication open
179. guest-mode
180. wpa-psk ascii MyKey

---

## 18️⃣ **Miscellaneous**

181. show controllers
182. test cable-diagnostics tdr interface Gi1/0/1
183. show cable-diagnostics tdr interface Gi1/0/1
184. archive download-sw tftp://server/image
185. boot system flash:<image.bin>
186. show boot
187. verify /md5 flash:<image.bin>
188. dir flash:
189. mkdir flash:backup
190. delete /recursive /force flash:backup
191. more flash:config.text
192. terminal length 0
193. terminal width 512
194. show platform
195. show license
196. license right-to-use activate ipservices acceptEULA
197. show ip http server status
198. ip http server
199. ip http secure-server
200. no ip http server

