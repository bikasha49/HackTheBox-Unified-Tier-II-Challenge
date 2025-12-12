# 🛡️ Vulnerability Assessment: Unified (Log4j CVE-2021-44228)

| **Target System** | Unified (HackTheBox) |
| :--- | :--- |
| **Vulnerability** | **Log4j (CVE-2021-44228)** |
| **Impact Level** | 🔴 Critical (Remote Code Execution) |
| **Tools Used** | **Wireshark, TCPDump**, Burp Suite, Rogue-JNDI, MongoDB |
| **Status** | ✅ Root Access Obtained |

---

## 📄 Executive Summary
This project demonstrates a black-box penetration test of the "Unified" machine. The assessment identified a critical Remote Code Execution (RCE) vulnerability in the **Unifi Network Application (v6.4.54)**.

By exploiting the **Log4j** vulnerability via JNDI injection, I bypassed authentication and gained initial access. Privilege escalation was achieved by enumerating a local MongoDB instance, extracting administrative hashes, and cracking credentials to gain **Root** access.

---

## 🔍 Phase 1: Reconnaissance
**Objective:** Identify the attack surface and confirm the vulnerability.

I performed an Nmap scan to identify running services. Port 8443 was hosting the Unifi Network Application. Accessing the web interface confirmed the version was **6.4.54**, which is vulnerable to the Log4j exploit.

**📸 Evidence #1: Nmap Scan & Version Identification**
<br><img src="2%20nmap%20to%20scan.png" alt="Nmap Scan Results" width="800"/>
<br><img src="4%20unified%20with%20version%20.png" alt="Unifi Version 6.4.54" width="800"/>

---

## 💥 Phase 2: Exploitation & Traffic Analysis
**Objective:** Leverage JNDI injection to gain a Reverse Shell.

### 2.1 Network Traffic Verification
Before launching the full attack, I verified that the target server could communicate back to my attacker machine. I initiated a test payload and analyzed the packets using **Wireshark** and **TCPDump** to confirm the LDAP connection attempt.

**📸 Evidence #2: Analyzing Network Traffic with TCPDump & Wireshark**
<br><img src="14%20tcpdump%20to%20analyze%20the%20trafic.png" alt="TCPDump Traffic Analysis" width="800"/>
<br><img src="12%20send%20the%20request%20again%20to%20see%20in%20wireshark%20.png" alt="Wireshark Packet Capture" width="800"/>

### 2.2 Execution (Burp Suite)
I utilized `rogue-jndi` to host a malicious LDAP server. I then intercepted the login request using **Burp Suite** and injected the JNDI payload into the `remember` field.

**📸 Evidence #3: Injecting the JNDI Payload via Burp Suite**
<br><img src="21%20rouge%20jndi%20made%20java-jar%20and%20target%20and%20copy%20that%20ldap%20mapping%20and%20repace%20it%20in%20remember%20section%20payload.png" alt="Burp Suite Payload Injection" width="800"/>

**📸 Evidence #4: Successful Reverse Shell (Initial Access)**
<br><img src="23%20nc%20-lvp%204444%20listening%20and%20identify%20unifi.png" alt="Reverse Shell Connection" width="800"/>

---

## 🔐 Phase 3: Privilege Escalation
**Objective:** Elevate privileges from `unifi` user to `root`.

Internal enumeration revealed a **MongoDB** instance running on localhost (port 27117). I connected to the database, dumped the `admin` collection, and discovered the administrator's password hash.

**📸 Evidence #5: Connecting to the Internal MongoDB**
<br><img src="29%20mongo%20port%2027117%20connecting%20to%20mongodb.png" alt="MongoDB Connection" width="800"/>

**📸 Evidence #6: Extracting Admin Hash for Cracking**
<br><img src="27%20name%20email%20shadow%20hash.png" alt="Admin Shadow Hash" width="800"/>

**Escalation:** After replacing the hash and logging into the dashboard as Administrator, I inspected the "Site Settings" and discovered the Root password stored in plain text.

**📸 Evidence #7: Discovery of Root Password in Dashboard**
<br><img src="33%20successfully%20can%20see%20the%20root%20password%20was%20NotACrackablePassword4U2022.png" alt="Root Password Exposed" width="800"/>

**📸 Evidence #8: Root Flag Capture 🚩**
<br><img src="34%20root%20flag%20.png" alt="Root Flag Capture" width="800"/>

---

## 🛡️ Remediation Strategy
To secure this environment, the following actions are recommended:
1.  **Patching:** Upgrade Unifi Network Application to version 6.5.55 or later immediately.
2.  **Configuration:** Apply the `log4j2.formatMsgNoLookups=true` mitigation to the JVM.
3.  **Network Segmentation:** Block outbound connections from the Unifi server to prevent external LDAP/JNDI lookups.

---
<div align="center">
  <b>Project Execution by <a href="https://www.linkedin.com/in/bikasha-gurung-082290288">Bikasha Gurung</a> | Cybersecurity Analyst</b>
  <br>
  <i>Open for SOC Analyst & Blue Team Opportunities</i>
</div>
