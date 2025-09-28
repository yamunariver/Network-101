Got it 👍 You want **Cisco ISE (Identity Services Engine) CLI commands**.
Cisco ISE is different from IOS/NX-OS – it runs on a hardened Linux OS with its own CLI.

Here’s a categorized list of **common Cisco ISE CLI commands**:

---

## 🔹 1. **System & Basic Commands**

* `show version` – Show ISE version.
* `show application status ise` – Check ISE application status (important).
* `application stop ise` – Stop ISE application.
* `application start ise` – Start ISE application.
* `application restart ise` – Restart ISE application.
* `application configure ise` – Launch configuration wizard.
* `show running-config` – Show running config.
* `show disk` – Check disk usage.
* `show memory` – Check memory usage.
* `show cpu` – Check CPU usage.
* `show logging system` – View system logs.
* `show logging application ise-psc.log` – View ISE process logs.

---

## 🔹 2. **Network & Connectivity**

* `ping <IP>` – Test connectivity.
* `ping <IP> source <interface>` – Ping using source interface.
* `traceroute <IP>` – Trace network path.
* `nslookup <hostname>` – DNS lookup.
* `show network interface` – Display interface settings.
* `configure terminal` → `interface GigabitEthernet 0` → `ip address <IP> <mask>` – Assign IP.
* `ip default-gateway <gateway-IP>` – Set default gateway.
* `show ip route` – Show routing table.
* `show ntp` – Check NTP sync status.
* `ntp server <server-IP>` – Configure NTP server.

---

## 🔹 3. **User & Access**

* `show user` – Show logged-in users.
* `show admin` – Show admin accounts.
* `configure terminal` → `username <user> password <pass> role admin` – Create new admin.
* `passwd admin` – Reset admin password.
* `techsupport` – Generate tech-support logs.
* `show application sessions` – Show current sessions.

---

## 🔹 4. **Certificates & HTTPS**

* `show crypto ca certificates` – Show installed certificates.
* `application configure ise` → select **certificate** options – Manage certs.
* `show ip http server status` – Check HTTPS service.
* `application stop ise` → update certs → `application start ise`.

---

## 🔹 5. **Backup & Restore**

* `show repository` – Show repositories.
* `repository <name>` – Configure repository (FTP/SFTP/NFS).
* `backup ise-<date> repository <name>` – Manual backup.
* `restore ise-<date> repository <name>` – Restore backup.
* `show backup history` – View backup history.

---

## 🔹 6. **Logs & Debugging**

* `show logging application ise-psc.log` – Policy service log.
* `show logging application ise-acs.log` – Access control log.
* `show logging application ise-radius.log` – RADIUS logs.
* `debug radius all` – Debug RADIUS.
* `debug ldap all` – Debug LDAP.
* `debug ad all` – Debug Active Directory join.
* `no debug all` – Stop debugging.

---

## 🔹 7. **Active Directory**

* `show application status ise` – Verify AD connectors.
* `show logging application ise-identity.log` – Identity services log.
* `application configure ise` → Active Directory settings.
* `test aaa group AD <username> <password> legacy` – Test AD login.

---

## 🔹 8. **Patch & Upgrade**

* `show version` – Check current version.
* `show repository <name>` – Verify repository before upgrade.
* `application upgrade <patch-file> <repository>` – Upgrade ISE.
* `application install <patch-file> <repository>` – Install patch.
* `application remove <patch-ID>` – Remove patch.
* `show application upgrade history` – View upgrade history.

---

## 🔹 9. **High Availability (Deployment Nodes)**

* `show application status ise` – Check primary/secondary role.
* `application configure ise` → deployment – Configure HA.
* `show cluster state` – View cluster state.
* `show application redundancy status` – Check redundancy.

---

## 🔹 10. **Useful Service Commands**

* `show application status ise | include Service` – See which services are UP/DOWN.
* `application stop ise && application start ise` – Restart all services.
* `clear configure all` – Factory reset ISE.

---

✅ **Most used daily commands** for admins:

* `show application status ise`
* `application stop ise` / `application start ise`
* `show logging application ise-radius.log`
* `backup ise-<date> repository <repo>`

---

Would you like me to prepare a **Cisco ISE CLI command cheat sheet (PDF)** like I did for IOS commands? That way you can quickly search while working on your ISE nodes.
