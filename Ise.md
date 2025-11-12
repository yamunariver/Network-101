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
