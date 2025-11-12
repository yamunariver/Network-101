Perfect — that’s a very useful clue 👇

> Switch log: authentication failed due to false credentials



This clearly means the endpoint (user or machine) is sending wrong or invalid credentials to Cisco ISE.
Now we just need to find why those credentials are wrong.

Let’s go through the likely reasons based on what you said earlier —
✅ Network fine for admin login,
❌ Not fine for domain login,
❌ Switch says "credentials false".


---

🔍 Possible Causes and Fixes

1. Expired or changed AD password

If the user recently changed their AD password, but the system’s 802.1X supplicant is still caching the old one → first or all attempts will fail.

On next reboot or manual reauthentication, it might succeed (after the OS updates credentials).


✅ Fix

Ask affected users to re-enter their credentials:

Windows:

1. Go to Network & Internet Settings → Ethernet/Wi-Fi → Authentication tab


2. Uncheck “Automatically use my Windows logon name and password”, apply, then recheck it.


3. Or manually remove saved credentials:

rundll32.exe keymgr.dll,KRShowKeyMgr

Remove old domain entries and reconnect.






---

2. Machine account password mismatch (domain trust issue)

Each domain computer has a machine account in AD with its own password that changes every 30 days.

If the computer was offline for long or lost sync, its machine password in AD doesn’t match → authentication fails.


✅ Check On the affected PC, log in locally (admin) and run:

nltest /sc_verify:yourdomain.local

If you see:

> “The secure channel is broken”



✅ Fix Rejoin the machine to the domain:

System Properties → Computer Name → Change → Workgroup → reboot → join domain again.


---

3. ISE Policy or Certificate Issue

If using EAP-TLS (certificate-based):

The client certificate may have expired or been revoked.

Or the CA chain in ISE is missing or invalid.


✅ Fix

In ISE → Operations → RADIUS → Live Logs, check the failure reason:

“Expired certificate”

“Client certificate not trusted”


Re-enroll or renew certificate if expired.



---

4. Supplicant misconfiguration (wrong EAP type)

If one PC is configured for PEAP-MSCHAPv2 and ISE expects EAP-TLS (or vice versa), authentication will fail due to credentials mismatch.


✅ Fix

Check network profile settings on Windows:

Control Panel → Network and Sharing Center → Manage Wired/Wireless Networks

Ensure the EAP type matches ISE policy (PEAP or EAP-TLS).



---

5. User vs Machine authentication confusion

Some setups fail if ISE expects machine authentication first but gets user credentials (or the other way around).

✅ Fix

Verify ISE policy:
Condition: Network Access:AuthenticationMethod EQUALS EAP-PEAP
Identity Source: “Internal Users” or “Active Directory” depending on setup.

If using both, enable “Allow Machine Authentication” in policy and configure switch for both:

authentication order mab dot1x
authentication priority dot1x mab
dot1x pae authenticator



---

🧰 Quick Checklist

Check	Command/Location	Expected

User password valid	Try AD login on another system	Success
Domain trust valid	nltest /sc_verify:<domain>	Success
ISE-AD connectivity	ISE → Admin → AD → Test Join	Success
Client certificate valid	certmgr.msc	Not expired
ISE log reason	ISE Live Logs	“Wrong credentials” = AD rejection



---

🧩 Next Step

Please share one failed log line from ISE Live Logs, for example:

Failure Reason

Username

Authentication Method (PEAP, EAP-TLS, etc.)


You can mask sensitive details — I’ll tell you exactly which side (user, AD, supplicant, or ISE) is causing the false-credentials error and what to do next.

Would you like to share that log entry?




Excellent question 👏 — let’s go deep into who sends EAPOL (EAP over LAN) and how it flows in an 802.1X authentication exchange.





Perfect 👍 — let’s go deeper into advanced configuration and use of 802.1X + MAB on Cisco switches, including concepts, flow, and real-world configurations.


---

🧠 Advanced 802.1X (Dot1x) + MAB Configuration & Use


---

⚙️ 1. 802.1X Authentication Architecture

Three main entities:

Component	Role

Supplicant	End device (user’s PC or laptop). Runs 802.1X client (e.g. Windows Wired AutoConfig).
Authenticator	Network access device (Cisco switch or AP). Controls access to the network port.
Authentication Server (RADIUS)	Cisco ISE / FreeRADIUS — validates identity and provides access policy.



---

🔄 2. Advanced Authentication Flow

Here’s how 802.1X + MAB fallback works (common in enterprises):

Step-by-Step:

1. Port detects a device connected → starts 802.1X process.


2. Switch sends EAPOL-Start → waits for supplicant response.


3. If no response → after timer expires → switch tries MAB.


4. MAB sends device’s MAC address to RADIUS for authentication.


5. RADIUS checks MAC address in database / policy set.


6. If allowed → RADIUS replies Access-Accept with VLAN assignment or ACL.


7. If rejected → port stays in unauthorized state.




---

🧩 3. Common Authentication Modes

Mode	Description

dot1x	Only 802.1X authentication allowed.
mab	Only MAC Authentication Bypass used.
dot1x + mab	Try 802.1X first; if no supplicant, fall back to MAB. (Most common)



---

🔧 4. Cisco Advanced Configuration Example

🔹 Global Configuration

aaa new-model
aaa authentication dot1x default group radius
aaa authorization network default group radius
aaa accounting update periodic 5

radius-server host 10.10.10.5 auth-port 1812 acct-port 1813 key cisco123
radius-server vsa send accounting
radius-server vsa send authentication

dot1x system-auth-control


---

🔹 Interface-Level Configuration

Example: Port GigabitEthernet1/0/10

interface GigabitEthernet1/0/10
 switchport mode access
 switchport access vlan 10
 authentication port-control auto
 mab
 dot1x pae authenticator
 dot1x timeout quiet-period 5
 dot1x timeout tx-period 10
 dot1x max-req 3
 dot1x max-reauth-req 3
 authentication event fail action authorize vlan 999
 authentication event server dead action authorize vlan 999
 authentication event server alive action reinitialize
 authentication order dot1x mab
 authentication priority dot1x mab
 authentication periodic
 authentication timer reauthenticate 3600
 spanning-tree portfast


---

🔹 Explanation of Key Commands

Command	Description

authentication port-control auto	Enables 802.1X on this port.
mab	Enables MAC Authentication Bypass fallback.
authentication order dot1x mab	Try 802.1X first, then MAB.
authentication priority dot1x mab	Gives priority to 802.1X.
authentication event fail action authorize vlan 999	If RADIUS not reachable → assign to guest VLAN.
authentication event server dead action authorize vlan 999	If RADIUS is down → move device to backup VLAN.
dot1x timeout quiet-period	Wait time before retry after failure.
dot1x timeout tx-period	Time between EAPOL requests.
authentication periodic	Periodically reauthenticate devices.
authentication timer reauthenticate 3600	Reauthenticate every 1 hour.



---

🪶 5. VLAN Assignment Options (Dynamic VLANs)

You can assign VLANs dynamically based on RADIUS replies.

Example RADIUS Reply Attributes:

Tunnel-Type = VLAN (13)

Tunnel-Medium-Type = IEEE-802 (6)

Tunnel-Private-Group-ID = 20


➡️ User authenticates → switch assigns VLAN 20 instead of default VLAN.

This is often used for:

Employee VLANs

Guest VLANs

Printer VLANs



---

🧾 6. MAB (MAC Authentication Bypass)

Used when devices can’t speak 802.1X (like IP phones, printers, cameras).

When 802.1X times out → switch automatically sends the MAC address to RADIUS.

RADIUS sees:

Username: 001122334455
Password: 001122334455

If the MAC exists in database → it’s authorized.


---

🔍 7. Verification & Troubleshooting

Check session status:

show authentication sessions
show authentication sessions interface Gi1/0/10

Check logs:

show logging | include DOT1X

Debug commands:

debug dot1x all
debug authentication
debug radius authentication

Clear session:

clear authentication sessions interface Gi1/0/10


---

🧠 8. Practical Use Cases

Scenario	Method Used

Employee PC (Windows AD-joined)	802.1X using user credentials (EAP-PEAP/MSCHAPv2).
Printer	MAB using MAC address whitelist.
IP Phone + PC behind it	Multi-domain authentication (voice + data VLAN).
Guest device	If no valid credentials → Guest VLAN assignment.
RADIUS unreachable	Server Dead VLAN (limited access).



---

📊 9. Multi-Authentication (IP Phone + PC)

You can authenticate both phone (via MAB) and PC (via 802.1X) on same port.

Example:

interface GigabitEthernet1/0/20
 switchport mode access
 switchport voice vlan 20
 authentication host-mode multi-domain
 mab
 dot1x pae authenticator
 authentication order mab dot1x
 authentication priority dot1x mab
 spanning-tree portfast

✅ Allows:

Phone → authenticates by MAB → placed in voice VLAN 20

PC → authenticates by 802.1X → placed in data VLAN



---

🧩 10. Security Enhancements

Feature	Description

critical VLAN	VLAN used when RADIUS server fails.
guest VLAN	VLAN used for unauthenticated devices.
restricted VLAN	Limited access VLAN for noncompliant devices.
reauthentication	Forces periodic validation to ensure compliance.



---

🧠 Summary Table

Feature	Purpose

802.1X	Secure authentication for capable devices.
MAB	Authentication for legacy/non-802.1X devices.
Guest VLAN	For unauthenticated access (internet only).
Critical VLAN	For fallback if RADIUS is unavailable.
Dynamic VLAN	Assign VLANs based on user identity.
Multi-domain	Support for phone + PC on same port.
Periodic Reauth	Ensures ongoing compliance.



---

Would you like me to draw a network flow diagram showing how Dot1x + MAB + VLAN assignment + ISE interaction works in one visual? It’ll make the concept extremely clear for real-world setup.
---

🧠 EAPOL (EAP over LAN) – Who Sends It and When


---

🔹 1. What is EAPOL?

EAPOL stands for Extensible Authentication Protocol over LAN.
It’s the protocol used to carry authentication messages between the Supplicant (end device) and the Authenticator (switch or AP) before the device gets full network access.

It operates at Layer 2 (Data Link layer) — before the device even gets an IP address.


---

🔑 2. The Three Main 802.1X Roles

Role	Device Example	Responsibility

Supplicant	PC, laptop, IP phone (client)	Sends EAPOL frames to authenticate itself.
Authenticator	Cisco switch or wireless AP	Controls access to the network port and passes EAP messages to the RADIUS server.
Authentication Server	Cisco ISE or FreeRADIUS	Validates credentials and returns Accept/Reject.



---

🔄 3. Who Sends What (EAPOL Flow)

Here’s the step-by-step EAPOL message exchange:


---

🧩 Step 1: Link Up

When the client connects to the port, the switch detects link-up.

The switch (Authenticator) sends an EAPOL-Start request to see if a supplicant is present.


Switch → PC: EAP-Request/Identity


---

🧩 Step 2: Supplicant Responds

The Supplicant (PC) replies with an EAPOL-Response/Identity message containing its username.


PC → Switch: EAP-Response/Identity (contains username)


---

🧩 Step 3: Switch Forwards to RADIUS

The switch (Authenticator) encapsulates this EAP response in a RADIUS Access-Request and forwards it to the RADIUS server.


Switch → RADIUS: Access-Request (EAP inside)


---

🧩 Step 4: RADIUS Server Validates

The RADIUS server (e.g. ISE) checks the credentials.

If successful → sends Access-Accept (with VLAN/ACL).

If failed → sends Access-Reject.


RADIUS → Switch: Access-Accept or Access-Reject


---

🧩 Step 5: Switch Informs Supplicant

The switch converts the RADIUS result back to EAPOL-Success or EAPOL-Failure and sends it to the PC.


Switch → PC: EAPOL-Success (if accepted)


---

🧠 Summary of Who Sends Each EAPOL Frame

Message Type	Sent By	Purpose

EAPOL-Start	Supplicant	To start 802.1X process manually (some clients send it immediately).
EAP-Request/Identity	Authenticator (Switch)	To ask client for identity (username).
EAP-Response/Identity	Supplicant	To send username/identity.
EAPOL-Success / Failure	Authenticator	To tell supplicant if authentication succeeded or failed.



---

🧩 Real-World Example Flow (Wired 802.1X)

[Supplicant PC]
   |  (EAPOL-Start)
   v
[Authenticator: Cisco Switch]
   |  (EAP-Request/Identity)
   v
[Supplicant PC]
   |  (EAP-Response/Identity)
   v
[Switch → RADIUS Server (ISE)]
   |  (Access-Request)
   v
[ISE: Validates Credentials]
   |  (Access-Accept)
   v
[Switch]
   |  (EAPOL-Success)
   v
[Supplicant PC – Network Access Granted ✅]


---

🧩 4. Quick Notes

EAPOL frames are not IP-based — they are Ethernet frames (Ethertype 0x888E).

If the supplicant does not respond to EAPOL requests → switch eventually moves to MAB.

When 802.1X succeeds, the port transitions from unauthorized to authorized state.



---

🧰 To Capture EAPOL in Action (for debugging):

You can run on the client or on a SPAN port:

sudo tcpdump -i eth0 ether proto 0x888e

You’ll see frames like:

EAPOL Start
EAPOL Request, Identity
EAPOL Response, Identity
EAPOL Success


---

✅ In short:

> The Supplicant (end-user device) initiates or responds using EAPOL frames,
and the Authenticator (switch) forwards and controls access based on RADIUS results.




---

Would you like me to show a packet-level EAPOL Wireshark example (with frame breakdown and explanation)? It’ll help visualize exactly what happens on the wire during Dot1x authentication.



Excellent 👍 — since your setup uses static IP addresses (no DHCP), let’s go through how to properly configure and handle dot1x + VLANs + static IPs in Cisco switches.

This is a common setup in secure enterprise or industrial environments where devices (like PCs, printers, IP phones, cameras) use fixed IPs.


---

🔹 1. What Changes When Using Static IPs

When clients have static IPs:

No DHCP request occurs, so ip helper-address isn’t needed.

The switch still performs 802.1X or MAB authentication before allowing traffic.

VLAN assignment and fallback logic still apply, but IP must match the VLAN.



---

🔹 2. Key Considerations

Aspect	Description

Static IP inside VLAN	Must belong to that VLAN’s subnet (e.g. VLAN10 = 10.10.10.0/24)
No IP helper	Not required
dot1x/MAB still work	Uses EAPOL (L2), not dependent on IP
Critical VLAN	Should have static addressing plan too
DNS / Gateway	Must be configured manually on each host



---

🔹 3. Example Core VLAN Config (Static IP Environment)

! Enable routing
Switch(config)# ip routing

! VLAN Definitions
Switch(config)# vlan 10
Switch(config-vlan)# name DATA_VLAN
Switch(config-vlan)# exit

Switch(config)# vlan 20
Switch(config-vlan)# name VOICE_VLAN
Switch(config-vlan)# exit

Switch(config)# vlan 30
Switch(config-vlan)# name MGMT_VLAN
Switch(config-vlan)# exit

Switch(config)# vlan 999
Switch(config-vlan)# name CRITICAL_VLAN
Switch(config-vlan)# exit

! VLAN Interfaces (SVIs)
Switch(config)# interface vlan 10
Switch(config-if)# ip address 10.10.10.1 255.255.255.0
Switch(config-if)# description DATA VLAN SVI
Switch(config-if)# no shutdown
Switch(config-if)# exit

Switch(config)# interface vlan 20
Switch(config-if)# ip address 10.10.20.1 255.255.255.0
Switch(config-if)# description VOICE VLAN SVI
Switch(config-if)# no shutdown
Switch(config-if)# exit

Switch(config)# interface vlan 999
Switch(config-if)# ip address 10.10.99.1 255.255.255.0
Switch(config-if)# description CRITICAL VLAN SVI
Switch(config-if)# no shutdown
Switch(config-if)# exit


---

🔹 4. Access Port + dot1x Configuration (for Static IP Devices)

Switch(config)# interface GigabitEthernet1/0/10
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 10
Switch(config-if)# switchport voice vlan 20
Switch(config-if)# authentication port-control auto
Switch(config-if)# mab
Switch(config-if)# dot1x pae authenticator
Switch(config-if)# authentication event server-dead action authorize vlan 999
Switch(config-if)# authentication event server-alive action reinitialize
Switch(config-if)# authentication order mab dot1x
Switch(config-if)# authentication priority dot1x mab
Switch(config-if)# authentication host-mode single-host
Switch(config-if)# spanning-tree portfast
Switch(config-if)# no shutdown


---

🔹 5. Static IP Assignment on End Device

For example, on a PC in VLAN 10:

Setting	Value

IP address	10.10.10.25
Subnet mask	255.255.255.0
Default gateway	10.10.10.1
DNS server	10.10.30.10 (or any internal DNS)


⚠️ Important: If RADIUS is down and the switch moves the port to VLAN 999 (Critical VLAN), the device’s static IP (10.10.10.25) won’t match VLAN 999 (10.10.99.x). It will lose network access.


---

🔹 6. How to Handle RADIUS Down with Static IPs

If RADIUS might go down occasionally:

Avoid using authentication event server-dead action authorize vlan 999

Instead, use fail-open so devices stay connected in their current VLAN:


Switch(config-if)# authentication event fail action authorize

✅ This keeps the port authorized even if RADIUS is unreachable.
No VLAN change happens → static IP continues working.


---

🔹 7. Verification Commands

show authentication sessions interface gi1/0/10 details
show dot1x interface gi1/0/10 detail
show radius statistics
show logging | include RADIUS


---

🔹 Summary

Feature	With Static IP

DHCP / Helper	❌ Not used
dot1x / MAB	✅ Works normally (Layer 2)
Critical VLAN	⚠️ Avoid if using static IPs
Fallback (server dead)	✅ Use fail action authorize
IP Gateway	Must be manually set per VLAN



---

Would you like me to show a best-practice configuration for static IP networks using dot1x + MAB with secure fallback (so users stay connected if RADIUS fails)?
It’s a clean design many Cisco engineers use in enterprise LANs.
