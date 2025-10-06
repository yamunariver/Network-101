Here’s a list of **advanced Cisco StackWise commands and tips** that go beyond the basics — useful for managing, troubleshooting, and optimizing switch stacks (e.g., **Catalyst 2960X, 9200, 9300, 3850, 9500 series**).

---

## 🔹 **1. Stack Status and Topology**

These help you understand how the stack is built and functioning.

```bash
# View overall stack status and switch priorities
show switch

# Display detailed stack member info (model, MAC, priority, etc.)
show switch detail

# Check stack ports status and cabling
show switch stack-ports

# Display stack topology (useful for ring vs. chain view)
show switch stack-ring speed
show switch stack-ring detail

# See which switch is active (master) and standby
show redundancy

# View stack election information
show switch stack-member

# Verify active/standby roles
show platform stack-manager all
```

---

## 🔹 **2. Stack Configuration Management**

```bash
# Change priority for stack election
switch 1 priority 15
switch 2 priority 10

# Rename stack member (persistent)
switch 2 name ACCESS02

# Change stack member number (after reload)
switch 2 renumber 1

# Save config for all switches
write memory all
```

> 💡 *Tip:* Always assign unique priorities — higher = more chance to be master.

---

## 🔹 **3. Stack Port and Hardware Troubleshooting**

```bash
# Check stack port errors (CRC, link issues)
show interfaces stack-port

# Verify stack cable connectivity and bandwidth
show switch stack-ring speed
show switch stack-ring utilization

# Check temperature and hardware health
show environment all

# Diagnose stack sync or mismatch issues
show platform stack-manager all
show platform stack-mac
```

> ⚠️ *If you see “Half-ring” in `show switch stack-ring detail`, one cable might be disconnected.*

---

## 🔹 **4. Software and Version Control**

All switches must run the **same IOS version**.
If not, you can use auto-upgrade or manually sync them.

```bash
# Check image consistency
show version | include Version
show switch detail | include Image

# Enable auto-upgrade for new stack members
software auto-upgrade enable

# Manually copy image to all members
copy flash:cat9k_iosxe.17.09.04.SPA.bin flash-switch2:
```

---

## 🔹 **5. Stack Synchronization and Configuration**

```bash
# Check config synchronization across members
show platform software configuration switch all

# Force sync config to all members
platform software config-sync all

# Display stack database
show platform software stack-mgr db
```

---

## 🔹 **6. Debug and Logging (use carefully in production)**

```bash
# Debug stack manager
debug platform stack-manager all

# Display log messages related to stack
show logging | include stack

# Monitor real-time stack events
terminal monitor
```

---

## 🔹 **7. Maintenance and Replacement**

```bash
# Gracefully remove a switch from the stack
switch 2 provision remove

# Replace failed switch (retain config)
switch 2 provision model WS-C9200-24T
write memory

# Reload a specific member
reload slot 2

# Reload the entire stack
reload
```

---

## 🔹 **8. Useful Show Summary**

| Purpose                   | Command                                           |
| ------------------------- | ------------------------------------------------- |
| Stack members summary     | `show switch`                                     |
| Detailed hardware view    | `show inventory`                                  |
| Stack cabling info        | `show switch stack-ports summary`                 |
| Active/standby role check | `show redundancy`                                 |
| IOS consistency check     | `show version`                                    |
| Config sync status        | `show platform software configuration switch all` |

---

Would you like me to tailor this to a **specific switch model (e.g., 9200 or 9300)** or **specific task** (like troubleshooting half-ring, upgrading stack members, or replacing one member)?
