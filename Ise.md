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
